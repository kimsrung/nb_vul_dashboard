import pytest
from httpx import AsyncClient


class TestMitreAttackAndReadiness:
    @pytest.mark.asyncio
    async def test_get_mitre_matrix(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/mitre/matrix", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "tactics" in data
        assert "total_techniques_mapped" in data
        assert "top_critical_techniques" in data
        assert len(data["tactics"]) == 14

        # Verify Initial Access tactic
        initial_access = next((t for t in data["tactics"] if t["id"] == "TA0001"), None)
        assert initial_access is not None
        assert initial_access["name"] == "Initial Access"
        assert "active_threats_count" in initial_access
        assert "affected_assets_count" in initial_access
        assert "critical_tier_exposure_count" in initial_access

    @pytest.mark.asyncio
    async def test_get_technique_detail(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/mitre/techniques/T1190", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "technique" in data
        tech = data["technique"]
        assert tech["id"] == "T1190"
        assert tech["name"] == "Exploit Public-Facing Application"
        assert tech["tactic_id"] == "TA0001"
        assert "adversary_perspective" in tech
        assert len(tech["compensating_controls"]) > 0

        # Verify compensating control structure
        ctrl = tech["compensating_controls"][0]
        assert "id" in ctrl
        assert "name" in ctrl
        assert "description" in ctrl
        assert "implementation_steps" in ctrl
        assert ctrl["downtime_required"] is False  # Safe!

        # Verify detection guidance
        assert "detection_guidance" in tech
        assert len(tech["detection_guidance"]["log_sources"]) > 0

    @pytest.mark.asyncio
    async def test_lookup_mitre_techniques(self, client: AsyncClient, admin_headers: dict):
        # Lookup OpenSSH regreSSHion CVE
        res = await client.get("/api/v1/mitre/lookup?cve=CVE-2024-6387", headers=admin_headers)
        assert res.status_code == 200
        techniques = res.json()
        assert len(techniques) > 0
        tech_ids = [t["id"] for t in techniques]
        assert "T1190" in tech_ids

    @pytest.mark.asyncio
    async def test_threat_readiness_endpoint(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/dashboard/threat-readiness", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "overall_readiness_score" in data
        assert 0.0 <= data["overall_readiness_score"] <= 100.0
        assert "readiness_grade" in data
        assert "tier_breakdown" in data
        assert len(data["tier_breakdown"]) == 3

        # Check Tier 1 (Bakong, SWIFT, CBS)
        tier1 = next((t for t in data["tier_breakdown"] if t["tier_level"] == 1), None)
        assert tier1 is not None
        assert "Bakong" in tier1["tier_name"]
        assert "readiness_percentage" in tier1
        assert "status" in tier1

        assert "top_recommended_actions" in data
        assert len(data["top_recommended_actions"]) > 0

    @pytest.mark.asyncio
    async def test_alerts_include_mitre_techniques(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/alerts?page=1&page_size=10", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        if len(data["items"]) > 0:
            first_alert = data["items"][0]
            assert "mitre_techniques" in first_alert
            assert isinstance(first_alert["mitre_techniques"], list)
            if len(first_alert["mitre_techniques"]) > 0:
                tech = first_alert["mitre_techniques"][0]
                assert "id" in tech
                assert "name" in tech
                assert "compensating_controls" in tech

    @pytest.mark.asyncio
    async def test_asset_detail_kb_includes_mitre_techniques(self, client: AsyncClient, admin_headers: dict):
        # Fetch first asset
        assets_res = await client.get("/api/v1/assets?page=1&page_size=1", headers=admin_headers)
        assert assets_res.status_code == 200
        assets = assets_res.json()["items"]
        if len(assets) > 0:
            asset_id = assets[0]["id"]
            detail_res = await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)
            assert detail_res.status_code == 200
            detail = detail_res.json()
            if len(detail["detections"]) > 0:
                first_det = detail["detections"][0]
                if first_det.get("knowledge_base"):
                    kb = first_det["knowledge_base"]
                    assert "mitre_techniques" in kb
                    assert isinstance(kb["mitre_techniques"], list)
