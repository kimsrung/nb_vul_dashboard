import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
class TestApiDocsAuthentication:
    async def test_docs_unauthorized_without_credentials(self, client: AsyncClient):
        # Accessing /docs without Basic Auth must be rejected
        res_docs = await client.get("/docs")
        assert res_docs.status_code == 401
        assert "Basic" in res_docs.headers.get("www-authenticate", "")

        # Accessing /openapi.json without Basic Auth must be rejected
        res_openapi = await client.get("/openapi.json")
        assert res_openapi.status_code == 401
        assert "Basic" in res_openapi.headers.get("www-authenticate", "")

    async def test_docs_unauthorized_with_wrong_credentials(self, client: AsyncClient):
        # Invalid username
        res_wrong_user = await client.get("/docs", auth=("invalid_user", settings.DOCS_PASSWORD))
        assert res_wrong_user.status_code == 401

        # Invalid password
        res_wrong_pass = await client.get("/openapi.json", auth=(settings.DOCS_USERNAME, "wrong_password_999"))
        assert res_wrong_pass.status_code == 401

    async def test_docs_authorized_with_valid_credentials(self, client: AsyncClient):
        # Valid credentials must successfully retrieve Swagger UI HTML
        res_docs = await client.get("/docs", auth=(settings.DOCS_USERNAME, settings.DOCS_PASSWORD))
        assert res_docs.status_code == 200
        assert "swagger" in res_docs.text.lower()
        assert "swagger-ui" in res_docs.text.lower()

        # Valid credentials must successfully retrieve OpenAPI JSON schema
        res_openapi = await client.get("/openapi.json", auth=(settings.DOCS_USERNAME, settings.DOCS_PASSWORD))
        assert res_openapi.status_code == 200
        schema = res_openapi.json()
        assert "openapi" in schema
        assert "/api/v1/assets" in schema.get("paths", {})
        assert "/api/v1/dashboard/summary" in schema.get("paths", {})

    async def test_redoc_is_disabled(self, client: AsyncClient):
        # ReDoc endpoint is explicitly disabled
        res = await client.get("/redoc")
        assert res.status_code == 404

    async def test_admin_updates_docs_credentials(self, client: AsyncClient, admin_headers: dict):
        original_user = settings.DOCS_USERNAME
        original_pass = settings.DOCS_PASSWORD

        try:
            # Update docs credentials via Admin Settings endpoint
            update_res = await client.post(
                "/api/v1/settings",
                json={
                    "docs_username": "nbc_security_lead",
                    "docs_password": "super_secure_vault_pass_2026",
                },
                headers=admin_headers,
            )
            assert update_res.status_code == 200
            data = update_res.json()
            assert data["docs_username"] == "nbc_security_lead"
            assert data["docs_password_masked"] == "••••••••"

            # Old credentials must now be rejected
            res_old = await client.get("/docs", auth=(original_user, original_pass))
            assert res_old.status_code == 401

            # New credentials must succeed
            res_new = await client.get("/docs", auth=("nbc_security_lead", "super_secure_vault_pass_2026"))
            assert res_new.status_code == 200

            res_new_openapi = await client.get("/openapi.json", auth=("nbc_security_lead", "super_secure_vault_pass_2026"))
            assert res_new_openapi.status_code == 200

        finally:
            # Restore original default credentials
            await client.post(
                "/api/v1/settings",
                json={
                    "docs_username": original_user,
                    "docs_password": original_pass,
                },
                headers=admin_headers,
            )
