import pytest
from httpx import AsyncClient


class TestAlertsCenter:
    @pytest.mark.asyncio
    async def test_list_alerts_structure_and_counts(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/alerts?page=1&page_size=5", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert "active_count" in data
        assert "total_exposed_servers" in data

        if len(data["items"]) > 0:
            alert = data["items"][0]
            assert "cve_id" in alert
            assert "severity" in alert
            assert "affected_product" in alert
            assert "suggested_solution" in alert
            assert "affected_assets" in alert

            # Check affected assets metadata including PoC and Owner
            if len(alert["affected_assets"]) > 0:
                srv = alert["affected_assets"][0]
                assert "asset_id" in srv
                assert "ip_address" in srv
                assert "evidence" in srv
                assert "confidence" in srv
                assert "poc_name" in srv
                assert "poc_email" in srv

    @pytest.mark.asyncio
    async def test_alerts_filtering_by_severity_and_match_type(self, client: AsyncClient, admin_headers: dict):
        # Filter by severity
        crit_res = await client.get("/api/v1/alerts?severity=Critical", headers=admin_headers)
        assert crit_res.status_code == 200
        for item in crit_res.json()["items"]:
            assert item["severity"] == "Critical"

        # Filter by match type
        proactive_res = await client.get("/api/v1/alerts?match_type=INVENTORY_PROACTIVE", headers=admin_headers)
        assert proactive_res.status_code == 200
        for item in proactive_res.json()["items"]:
            assert item["match_type"] == "INVENTORY_PROACTIVE"

    @pytest.mark.asyncio
    async def test_resolve_and_reopen_alert(self, client: AsyncClient, admin_headers: dict):
        # Find first alert
        list_res = await client.get("/api/v1/alerts?page=1&page_size=1", headers=admin_headers)
        items = list_res.json()["items"]
        if not items:
            pytest.skip("No alerts present to test resolution")

        alert_id = items[0]["id"]

        # 1. Resolve alert via /resolve
        resolve_res = await client.post(
            f"/api/v1/alerts/{alert_id}/resolve",
            headers=admin_headers,
            json={"status": "Remediated", "resolution_notes": "Patched OpenSSH to version 9.8p1"}
        )
        assert resolve_res.status_code == 200
        assert resolve_res.json()["status"] == "Remediated"
        assert resolve_res.json()["is_resolved"] is True

        # 2. Check that filter is_resolved=true returns it
        resolved_list = (await client.get("/api/v1/alerts?is_resolved=true", headers=admin_headers)).json()
        assert any(a["id"] == alert_id for a in resolved_list["items"])

        # 3. Revert back to Pending
        revert_res = await client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            headers=admin_headers,
            json={"status": "Pending", "resolution_notes": "Reopened for re-evaluation"}
        )
        assert revert_res.status_code == 200
        assert revert_res.json()["status"] == "Pending"
        assert revert_res.json()["is_resolved"] is False
