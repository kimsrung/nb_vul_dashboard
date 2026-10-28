import base64
import json
import time
import pytest
from httpx import AsyncClient
import jwt

from app.core.config import settings
from app.core.security import create_access_token


class TestVAPTSecuritySuite:
    """Defensive Security & VAPT Automated Test Suite.
    Validates OWASP API Top 10 vulnerabilities:
    - Broken Authentication & JWT tampering (API2:2023)
    - Broken Object & Function Level Authorization / RBAC (API1:2023, API5:2023)
    - Injection & Query Parameter tampering (API8:2023)
    - Security Misconfiguration & API Docs Protection (API7:2023)
    """

    # =========================================================================
    # 1. JWT & Authentication Security (OWASP API2:2023)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_jwt_tampered_signature_rejected(self, client: AsyncClient, viewer_headers: dict):
        """Verify that altering token payload or signature returns 401 Unauthorized."""
        valid_token = viewer_headers["Authorization"].split(" ")[1]
        parts = valid_token.split(".")
        # Corrupt the signature bytes
        tampered_token = f"{parts[0]}.{parts[1]}.bad_signature_bytes"

        res = await client.get("/api/v1/assets", headers={"Authorization": f"Bearer {tampered_token}"})
        assert res.status_code == 401
        assert "Could not validate credentials" in res.json()["detail"]

    @pytest.mark.asyncio
    async def test_jwt_none_algorithm_tampering_rejected(self, client: AsyncClient):
        """Verify that 'alg: none' token is strictly rejected by algorithm pinning."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": "admin",
            "role": "admin",
            "exp": int(time.time()) + 3600
        }).encode()).decode().rstrip("=")
        none_token = f"{header}.{payload}."

        res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {none_token}"})
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_jwt_expired_token_rejected(self, client: AsyncClient):
        """Verify that expired JWT token is immediately rejected."""
        expired_payload = {
            "sub": "admin",
            "role": "admin",
            "exp": int(time.time()) - 3600,  # 1 hour in the past
        }
        expired_token = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

        res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_jwt_missing_subject_rejected(self, client: AsyncClient):
        """Verify that token without subject ('sub') claim is rejected."""
        invalid_payload = {
            "role": "admin",
            "exp": int(time.time()) + 3600,
        }
        token = jwt.encode(invalid_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

        res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_login_brute_force_rate_limiting(self, client: AsyncClient):
        """Verify repeated failed login attempts trigger 429 Too Many Requests."""
        from app.core.security import login_limiter
        # Clear rate limiter state for test determinism
        login_limiter._attempts.clear()

        # Send 10 consecutive failed attempts
        for _ in range(10):
            res = await client.post("/api/v1/auth/login", json={"username": "victim_user", "password": "wrongpassword"})
            assert res.status_code == 401

        # The 11th attempt must be throttled with 429 Too Many Requests
        throttled_res = await client.post("/api/v1/auth/login", json={"username": "victim_user", "password": "wrongpassword"})
        assert throttled_res.status_code == 429
        assert "Too many failed login attempts" in throttled_res.json()["detail"]

        # Clean up limiter
        login_limiter._attempts.clear()

    # =========================================================================
    # 2. RBAC Privilege Boundaries Across All 4 Roles (OWASP API1 & API5:2023)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_viewer_role_cannot_trigger_sync_operations(self, client: AsyncClient, viewer_headers: dict, analyst_headers: dict):
        """Viewer and Analyst roles must not be able to trigger Qualys or MISP background syncs."""
        # Qualys sync trigger
        res_qualys = await client.post("/api/v1/dashboard/sync?mode=delta", headers=viewer_headers)
        assert res_qualys.status_code == 403

        # MISP sync trigger
        res_misp = await client.post("/api/v1/misp/sync", headers=viewer_headers)
        assert res_misp.status_code == 403

        res_misp_analyst = await client.post("/api/v1/misp/sync", headers=analyst_headers)
        assert res_misp_analyst.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_access_audit_logs(self, client: AsyncClient):
        """Unauthenticated requests to audit logs must be rejected with 401."""
        res = await client.get("/api/v1/audit-logs")
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_viewer_can_read_audit_logs_as_auditor(self, client: AsyncClient, viewer_headers: dict):
        """Viewer role (Read-only auditor) has read-only access to audit logs."""
        res = await client.get("/api/v1/audit-logs", headers=viewer_headers)
        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_viewer_and_owner_cannot_modify_settings(self, client: AsyncClient, viewer_headers: dict, owner_headers: dict):
        """Viewer and Owner roles cannot read or alter system configuration or test integrations."""
        # Read attempt (Admin only)
        res_read_v = await client.get("/api/v1/settings", headers=viewer_headers)
        assert res_read_v.status_code == 403

        res_read_o = await client.get("/api/v1/settings", headers=owner_headers)
        assert res_read_o.status_code == 403

        payload = {"qualys_mock_mode": True}

        # Viewer attempt
        res_v = await client.post("/api/v1/settings", headers=viewer_headers, json=payload)
        assert res_v.status_code == 403

        # Owner attempt
        res_o = await client.post("/api/v1/settings", headers=owner_headers, json=payload)
        assert res_o.status_code == 403

        # Connection test attempts
        res_test = await client.post("/api/v1/settings/test-telegram", headers=viewer_headers, json={})
        assert res_test.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_manage_users(self, client: AsyncClient, analyst_headers: dict):
        """Security Analyst cannot create or delete user accounts (Admin only)."""
        new_user = {
            "username": "attacker",
            "email": "attacker@evil.com",
            "password": "Password123!",
            "role": "admin",
        }
        res = await client.post("/api/v1/auth/users", headers=analyst_headers, json=new_user)
        assert res.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_has_full_administrative_access(self, client: AsyncClient, admin_headers: dict):
        """Admin has full access to settings, user management, and audit logs."""
        res_settings = await client.get("/api/v1/settings", headers=admin_headers)
        assert res_settings.status_code == 200

        res_audit = await client.get("/api/v1/audit-logs?page=1&page_size=5", headers=admin_headers)
        assert res_audit.status_code == 200

    # =========================================================================
    # 3. API Documentation Protection (Basic Auth)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_swagger_docs_unauthenticated_rejected(self, client: AsyncClient):
        """Verify /docs and /openapi.json reject unauthenticated requests."""
        res_docs = await client.get("/docs")
        assert res_docs.status_code == 401

        res_openapi = await client.get("/openapi.json")
        assert res_openapi.status_code == 401

    @pytest.mark.asyncio
    async def test_swagger_docs_valid_credentials_accepted(self, client: AsyncClient):
        """Verify /docs and /openapi.json are accessible with valid HTTP Basic credentials."""
        basic_auth = (settings.DOCS_USERNAME, settings.DOCS_PASSWORD)
        res_docs = await client.get("/docs", auth=basic_auth)
        assert res_docs.status_code == 200
        assert "swagger-ui" in res_docs.text

        res_openapi = await client.get("/openapi.json", auth=basic_auth)
        assert res_openapi.status_code == 200
        assert "openapi" in res_openapi.json()

    # =========================================================================
    # 4. Injection Resilience & SQL Query Parameterization (OWASP API8:2023)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_sql_injection_payloads_in_search_and_filter(self, client: AsyncClient, admin_headers: dict):
        """Verify SQL injection strings in query params do not cause 500 errors or leaks."""
        sqli_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE assets; --",
            "admin' --",
            "\" OR \"\"=\"",
            "') UNION SELECT 1, 2, 3 --",
        ]
        for payload in sqli_payloads:
            # Asset search injection attempt
            res_assets = await client.get(f"/api/v1/assets?search={payload}", headers=admin_headers)
            assert res_assets.status_code == 200, f"SQLi payload failed on assets search: {payload}"
            assert isinstance(res_assets.json().get("items"), list)

            # Alerts search injection attempt
            res_alerts = await client.get(f"/api/v1/alerts?search={payload}", headers=admin_headers)
            assert res_alerts.status_code == 200, f"SQLi payload failed on alerts search: {payload}"
            assert isinstance(res_alerts.json().get("items"), list)

            # Audit logs search injection attempt
            res_logs = await client.get(f"/api/v1/audit-logs?search={payload}", headers=admin_headers)
            assert res_logs.status_code == 200, f"SQLi payload failed on audit logs search: {payload}"
            assert isinstance(res_logs.json().get("items"), list)
