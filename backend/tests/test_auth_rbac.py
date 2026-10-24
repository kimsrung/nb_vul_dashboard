import pytest
from httpx import AsyncClient


class TestAuthenticationAndRBAC:
    @pytest.mark.asyncio
    async def test_login_successful_for_all_roles(self, client: AsyncClient):
        roles_creds = [
            ("admin", "admin123", "admin"),
            ("analyst", "analyst123", "analyst"),
            ("owner_appcore", "owner123", "owner"),
            ("viewer", "viewer123", "viewer"),
        ]
        for username, password, expected_role in roles_creds:
            res = await client.post("/api/v1/auth/login", json={"username": username, "password": password})
            assert res.status_code == 200, f"Login failed for {username}: {res.text}"
            data = res.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
            assert data["role"] == expected_role
            assert data["username"] == username

    @pytest.mark.asyncio
    async def test_login_invalid_credentials_returns_401(self, client: AsyncClient):
        res = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
        assert res.status_code == 401
        assert "Incorrect username or password" in res.json()["detail"]

    @pytest.mark.asyncio
    async def test_unauthenticated_request_rejected(self, client: AsyncClient):
        res = await client.get("/api/v1/assets")
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_profile(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert res.status_code == 200
        user = res.json()
        assert user["username"] == "admin"
        assert user["role"] == "admin"
        assert user["is_active"] is True

    @pytest.mark.asyncio
    async def test_viewer_rbac_permissions(self, client: AsyncClient, viewer_headers: dict):
        # Viewer can read assets
        res = await client.get("/api/v1/assets", headers=viewer_headers)
        assert res.status_code == 200

        # Viewer cannot assign owner or patch asset (requires analyst or admin)
        patch_res = await client.patch("/api/v1/assets/1/owner", headers=viewer_headers, json={"server_name": "hacked"})
        assert patch_res.status_code == 403

        # Viewer cannot manage users (requires admin)
        user_res = await client.get("/api/v1/auth/users", headers=viewer_headers)
        assert user_res.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_rbac_permissions(self, client: AsyncClient, analyst_headers: dict):
        # Analyst can read assets and audit logs
        res = await client.get("/api/v1/assets", headers=analyst_headers)
        assert res.status_code == 200

        # Analyst cannot delete assets (requires admin)
        del_res = await client.request("DELETE", "/api/v1/assets/1", headers=analyst_headers, json={"reason": "test"})
        assert del_res.status_code == 403

        # Analyst cannot update system settings (requires admin)
        settings_res = await client.post("/api/v1/settings", headers=analyst_headers, json={"misp_enabled": True})
        assert settings_res.status_code == 403

    @pytest.mark.asyncio
    async def test_owner_role_scoping(self, client: AsyncClient, owner_headers: dict, admin_headers: dict):
        # Admin gets total count of all assets
        admin_res = await client.get("/api/v1/assets", headers=admin_headers)
        assert admin_res.status_code == 200
        admin_assets = admin_res.json()
        total_assets = admin_assets["total"]

        # Owner gets only their assigned servers
        owner_res = await client.get("/api/v1/assets", headers=owner_headers)
        assert owner_res.status_code == 200
        owner_assets = owner_res.json()

        # All assets returned to owner must belong to owner_appcore
        for item in owner_assets["items"]:
            assert item["owner_username"] == "owner_appcore"
            assert item["owner_id"] is not None
        assert owner_assets["total"] <= total_assets
