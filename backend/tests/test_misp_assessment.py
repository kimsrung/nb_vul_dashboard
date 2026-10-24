import pytest
from httpx import AsyncClient


class TestMispThreatAssessment:
    @pytest.mark.asyncio
    async def test_misp_feed_listing(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/misp/feed", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        if len(data) > 0:
            item = data[0]
            assert "cve_id" in item
            assert "title" in item
            assert "affected_product" in item
            assert "match_type" in item
            assert "affected_assets_count" in item

    @pytest.mark.asyncio
    async def test_misp_summary_kpi_metrics(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/misp/summary", headers=admin_headers)
        assert res.status_code == 200
        summary = res.json()
        assert "total_advisories" in summary
        assert "pre_scan_matches" in summary
        assert "qualys_confirmed" in summary
        assert "at_risk_assets" in summary

    @pytest.mark.asyncio
    async def test_misp_simulate_zeromq_threat_event(self, client: AsyncClient, admin_headers: dict):
        sample_event = {
            "Event": {
                "id": "77777",
                "info": "FS-ISAC Advisory: OpenSSH Remote Code Execution regreSSHion",
                "orgc_id": "1",
                "Orgc": {"name": "FS-ISAC"},
                "affected_product": "openssh",
                "vulnerable_versions": "< 9.8p1",
                "fixed_versions": ">= 9.8p1",
                "severity": "Critical",
                "cvss_score": 8.1,
                "Tag": [
                    {"name": "FS-ISAC"},
                    {"name": "vulnerability:CVE-2024-6387"}
                ],
                "Attribute": [
                    {"type": "vulnerability", "value": "CVE-2024-6387"}
                ]
            }
        }

        # 1. Post to simulation endpoint
        sim_res = await client.post("/api/v1/alerts/simulate-event", headers=admin_headers, json=sample_event)
        assert sim_res.status_code == 200
        data = sim_res.json()
        assert data.get("success") is True
        assert "ZeroMQ threat event processed" in data.get("message")

        # 2. Check audit log for MISP_EVENT_TRIGGERED
        audit_res = await client.get("/api/v1/audit-logs?search=CVE-2024-6387", headers=admin_headers)
        assert audit_res.status_code == 200
        items = audit_res.json()["items"]
        assert len(items) > 0
        trigger_log = next((l for l in items if l["action"] == "MISP_EVENT_TRIGGERED"), None)
        assert trigger_log is not None
        assert trigger_log["target_id"] == "CVE-2024-6387"
        assert "affected_assets_count" in trigger_log["details"]

    @pytest.mark.asyncio
    async def test_misp_simulate_event_requires_admin(self, client: AsyncClient, viewer_headers: dict):
        res = await client.post("/api/v1/alerts/simulate-event", headers=viewer_headers, json={})
        assert res.status_code == 403
