import pytest
from httpx import AsyncClient


class TestAssetInventoryAndPoC:
    @pytest.mark.asyncio
    async def test_list_assets_pagination_and_structure(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/assets?page=1&page_size=5", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert "total_pages" in data
        assert len(data["items"]) <= 5

        # Check required schema fields on first item
        item = data["items"][0]
        assert "id" in item
        assert "qualys_id" in item
        assert "ip_address" in item
        assert "risk_score" in item
        assert "risk_level" in item
        assert "poc_name" in item
        assert "poc_email" in item

    @pytest.mark.asyncio
    async def test_asset_filters(self, client: AsyncClient, admin_headers: dict):
        # Filter by risk level
        res_crit = await client.get("/api/v1/assets?risk_level=Critical", headers=admin_headers)
        assert res_crit.status_code == 200
        for item in res_crit.json()["items"]:
            assert item["risk_level"] == "Critical"

        # Filter by OS family
        res_os = await client.get("/api/v1/assets?os_family=Linux", headers=admin_headers)
        assert res_os.status_code == 200
        for item in res_os.json()["items"]:
            assert item["os_family"] == "Linux"

        # Filter by is_risky
        res_risky = await client.get("/api/v1/assets?is_risky=true", headers=admin_headers)
        assert res_risky.status_code == 200
        for item in res_risky.json()["items"]:
            assert item["is_risky"] is True

    @pytest.mark.asyncio
    async def test_get_asset_detail_and_software(self, client: AsyncClient, admin_headers: dict):
        # Fetch first asset ID
        list_res = await client.get("/api/v1/assets?page=1&page_size=1", headers=admin_headers)
        asset_id = list_res.json()["items"][0]["id"]

        # Asset detail dossier
        detail_res = await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == asset_id
        assert "detections" in detail

        # Asset software inventory
        sw_res = await client.get(f"/api/v1/assets/{asset_id}/software", headers=admin_headers)
        assert sw_res.status_code == 200
        assert isinstance(sw_res.json(), list)

    @pytest.mark.asyncio
    async def test_update_asset_poc_and_metadata(self, client: AsyncClient, admin_headers: dict):
        list_res = await client.get("/api/v1/assets?page=1&page_size=1", headers=admin_headers)
        asset_id = list_res.json()["items"][0]["id"]

        payload = {
            "server_name": "test-host-poc-unit",
            "poc_name": "Sok Visal",
            "poc_email": "sok.visal@nbc.gov.kh"
        }
        patch_res = await client.patch(f"/api/v1/assets/{asset_id}/owner", headers=admin_headers, json=payload)
        assert patch_res.status_code == 200
        data = patch_res.json()
        assert data["server_name"] == "test-host-poc-unit"
        assert data["poc_name"] == "Sok Visal"
        assert data["poc_email"] == "sok.visal@nbc.gov.kh"

        # Verify search by PoC name finds this updated asset
        search_res = await client.get("/api/v1/assets?search=Visal", headers=admin_headers)
        assert search_res.status_code == 200
        assert any(a["id"] == asset_id for a in search_res.json()["items"])

        # Verify search by PoC email finds this updated asset
        search_email_res = await client.get("/api/v1/assets?search=sok.visal", headers=admin_headers)
        assert search_email_res.status_code == 200
        assert any(a["id"] == asset_id for a in search_email_res.json()["items"])

    @pytest.mark.asyncio
    async def test_assign_owner_validation_enforces_owner_role(self, client: AsyncClient, admin_headers: dict):
        list_res = await client.get("/api/v1/assets?page=1&page_size=1", headers=admin_headers)
        asset_id = list_res.json()["items"][0]["id"]

        # Fetch users to get admin and owner IDs
        users_res = await client.get("/api/v1/auth/users", headers=admin_headers)
        users = users_res.json()
        admin_user = next(u for u in users if u["role"] == "admin")
        owner_user = next(u for u in users if u["role"] == "owner")

        # 1. Reject assigning admin as owner
        bad_res = await client.patch(f"/api/v1/assets/{asset_id}/owner", headers=admin_headers, json={"owner_id": admin_user["id"]})
        assert bad_res.status_code == 400
        assert "Only users with role 'owner' can be assigned" in bad_res.json()["detail"]

        # 2. Accept assigning valid owner
        good_res = await client.patch(f"/api/v1/assets/{asset_id}/owner", headers=admin_headers, json={"owner_id": owner_user["id"]})
        assert good_res.status_code == 200
        assert good_res.json()["owner_id"] == owner_user["id"]
        assert good_res.json()["owner_username"] == owner_user["username"]

        # 3. Unassign owner (0)
        unassign_res = await client.patch(f"/api/v1/assets/{asset_id}/owner", headers=admin_headers, json={"owner_id": 0})
        assert unassign_res.status_code == 200
        assert unassign_res.json()["owner_id"] is None
        assert unassign_res.json()["owner_username"] is None

    @pytest.mark.asyncio
    async def test_owners_dropdown_filters_only_owner_role(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/auth/owners", headers=admin_headers)
        assert res.status_code == 200
        owners = res.json()
        assert len(owners) > 0
        for o in owners:
            assert o["role"] == "owner"
            assert o["username"] not in ("admin", "analyst", "viewer")

    @pytest.mark.asyncio
    async def test_asset_inventory_default_sorting_by_critical_vulns(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/assets?page=1&page_size=10", headers=admin_headers)
        assert res.status_code == 200
        items = res.json()["items"]
        assert len(items) > 1

        # Check raw Qualys severity fields
        for item in items:
            assert "critical_vulns" in item
            assert "high_vulns" in item
            assert "medium_vulns" in item
            assert "low_vulns" in item
            assert "info_vulns" in item
            assert "total_vulns" in item
            assert isinstance(item["critical_vulns"], int)
            assert isinstance(item["high_vulns"], int)

        # Default ordering should be critical_vulns descending
        for i in range(len(items) - 1):
            assert items[i]["critical_vulns"] >= items[i + 1]["critical_vulns"]

    @pytest.mark.asyncio
    async def test_asset_inventory_sorting_options(self, client: AsyncClient, admin_headers: dict):
        # Sort by high_vulns descending
        high_res = await client.get("/api/v1/assets?sort_by=high_vulns&sort_order=desc&page_size=5", headers=admin_headers)
        assert high_res.status_code == 200
        high_items = high_res.json()["items"]
        for i in range(len(high_items) - 1):
            assert high_items[i]["high_vulns"] >= high_items[i + 1]["high_vulns"]

        # Sort by total_vulns descending
        total_res = await client.get("/api/v1/assets?sort_by=total_vulns&sort_order=desc&page_size=5", headers=admin_headers)
        assert total_res.status_code == 200
        total_items = total_res.json()["items"]
        for i in range(len(total_items) - 1):
            assert total_items[i]["total_vulns"] >= total_items[i + 1]["total_vulns"]

    @pytest.mark.asyncio
    async def test_asset_edge_cases(self, client: AsyncClient, admin_headers: dict):
        # 1. Whitespace search should not crash and should return standard results
        empty_search = await client.get("/api/v1/assets?search=%20%20", headers=admin_headers)
        assert empty_search.status_code == 200
        assert empty_search.json()["total"] > 0

        # 2. Non-existent asset ID returns 404
        missing_asset = await client.get("/api/v1/assets/99999999", headers=admin_headers)
        assert missing_asset.status_code == 404

        # 3. Non-existent CVE filter returns empty items cleanly
        missing_cve = await client.get("/api/v1/assets?cve=CVE-9999-99999", headers=admin_headers)
        assert missing_cve.status_code == 200
        assert missing_cve.json()["total"] == 0
        assert len(missing_cve.json()["items"]) == 0

        # 4. is_active filter handles boolean values cleanly
        active_res = await client.get("/api/v1/assets?is_active=true", headers=admin_headers)
        assert active_res.status_code == 200
        for a in active_res.json()["items"]:
            assert a["is_active"] is True
