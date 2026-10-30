import pytest
from httpx import AsyncClient


class TestDashboardSummaryAndSync:
    @pytest.mark.asyncio
    async def test_dashboard_summary_structure_and_metrics(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/dashboard/summary", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()

        # Core KPI metrics
        assert "total_assets" in data
        assert "risky_assets" in data
        assert "total_vulns" in data
        assert isinstance(data["total_assets"], int)
        assert data["total_assets"] > 0

        # Raw Qualys 5-severity breakdown
        assert "severity_breakdown" in data
        sev = data["severity_breakdown"]
        assert "sev5" in sev
        assert "sev4" in sev
        assert "sev3" in sev
        assert "sev2" in sev
        assert "sev1" in sev
        assert isinstance(sev["sev5"], int)
        assert isinstance(sev["sev4"], int)
        assert isinstance(sev["sev3"], int)
        assert isinstance(sev["sev2"], int)
        assert isinstance(sev["sev1"], int)

        # MISP Threat Advisories metrics
        assert "misp_advisories_count" in data
        assert "misp_matched_assets_count" in data
        assert isinstance(data["misp_advisories_count"], int)
        assert isinstance(data["misp_matched_assets_count"], int)

        # Risk distribution & OS breakdown
        assert "risk_distribution" in data
        assert "top_os_families" in data
        assert "threat_intel_summary" in data
        assert "recent_risky_assets" in data
        assert isinstance(data["recent_risky_assets"], list)

    @pytest.mark.asyncio
    async def test_dashboard_summary_owner_scoping(
        self, client: AsyncClient, admin_headers: dict, owner_headers: dict
    ):
        admin_res = await client.get("/api/v1/dashboard/summary", headers=admin_headers)
        assert admin_res.status_code == 200
        admin_total = admin_res.json()["total_assets"]

        owner_res = await client.get("/api/v1/dashboard/summary", headers=owner_headers)
        assert owner_res.status_code == 200
        owner_data = owner_res.json()

        # Owner total must be strictly scoped
        assert owner_data["total_assets"] <= admin_total
        assert owner_data["total_assets"] > 0

    @pytest.mark.asyncio
    async def test_dashboard_summary_unauthenticated_returns_401(self, client: AsyncClient):
        res = await client.get("/api/v1/dashboard/summary")
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_qualys_sync_trigger_and_rbac(
        self, client: AsyncClient, admin_headers: dict, viewer_headers: dict
    ):
        # Viewer cannot trigger Qualys scan sync
        viewer_sync = await client.post("/api/v1/sync/qualys?mode=delta", headers=viewer_headers)
        assert viewer_sync.status_code == 403

        # Admin can trigger Qualys scan sync
        admin_sync = await client.post("/api/v1/sync/qualys?mode=delta", headers=admin_headers)
        assert admin_sync.status_code in (200, 202)
        assert admin_sync.json()["success"] is True
