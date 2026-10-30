import pytest
from httpx import AsyncClient


class TestMispThreatAssessment:
    @pytest.mark.asyncio
    async def test_misp_feed_listing(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/misp/feed", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert "total_events" in data
        items = data["items"]
        assert isinstance(items, list)
        if len(items) > 0:
            item = items[0]
            assert "cve_id" in item
            assert "title" in item
            assert "affected_product" in item
            assert "match_type" in item
            assert "affected_assets_count" in item
            assert "misp_event_id" in item
            assert "misp_event_date" in item
            assert "created_at" in item

    @pytest.mark.asyncio
    async def test_misp_feed_analyst_allowed_viewer_rejected(self, client: AsyncClient, analyst_headers: dict, viewer_headers: dict):
        res_analyst = await client.get("/api/v1/misp/feed", headers=analyst_headers)
        assert res_analyst.status_code == 200

        res_viewer = await client.get("/api/v1/misp/feed", headers=viewer_headers)
        assert res_viewer.status_code == 403

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

    @pytest.mark.asyncio
    async def test_misp_sync_feed_endpoint(self, client: AsyncClient, admin_headers: dict):
        res = await client.post("/api/v1/sync/misp", headers=admin_headers)
        assert res.status_code in (200, 202)
        data = res.json()
        assert data.get("success") is True
        assert "job_id" in data
        assert data.get("status") == "running"

        # Verify job status
        status_res = await client.get("/api/v1/sync/status?source=misp", headers=admin_headers)
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert "is_running" in status_data

    @pytest.mark.asyncio
    async def test_misp_sync_feed_rbac(self, client: AsyncClient, viewer_headers: dict, analyst_headers: dict):
        # Viewer rejected
        viewer_res = await client.post("/api/v1/sync/misp", headers=viewer_headers)
        assert viewer_res.status_code == 403

        # Analyst rejected (Sync Feed is admin-only)
        analyst_res = await client.post("/api/v1/sync/misp", headers=analyst_headers)
        assert analyst_res.status_code == 403

    @pytest.mark.asyncio
    async def test_misp_feed_sorting_and_filtering(self, client: AsyncClient, admin_headers: dict):
        # 1. Default sort should be cve_id descending
        default_res = await client.get("/api/v1/misp/feed", headers=admin_headers)
        assert default_res.status_code == 200
        default_items = default_res.json()["items"]
        if len(default_items) > 1:
            for i in range(len(default_items) - 1):
                assert default_items[i]["cve_id"] >= default_items[i + 1]["cve_id"]

        # 2. Sort by cve_id ascending
        asc_res = await client.get("/api/v1/misp/feed?sort_by=cve_id&sort_order=asc", headers=admin_headers)
        assert asc_res.status_code == 200
        asc_items = asc_res.json()["items"]
        if len(asc_items) > 1:
            for i in range(len(asc_items) - 1):
                assert asc_items[i]["cve_id"] <= asc_items[i + 1]["cve_id"]

        # 3. Sort by affected_assets_count descending
        sort_res = await client.get("/api/v1/misp/feed?sort_by=affected_assets_count&sort_order=desc", headers=admin_headers)
        assert sort_res.status_code == 200
        items = sort_res.json()["items"]
        if len(items) > 1:
            for i in range(len(items) - 1):
                assert items[i]["affected_assets_count"] >= items[i + 1]["affected_assets_count"]

        # 4. Filter by severity
        crit_res = await client.get("/api/v1/misp/feed?severity=Critical", headers=admin_headers)
        assert crit_res.status_code == 200
        for item in crit_res.json()["items"]:
            assert item["severity"] == "Critical"

    @pytest.mark.asyncio
    async def test_misp_feed_edge_cases(self, client: AsyncClient, admin_headers: dict):
        # 1. Whitespace search handled cleanly
        ws_res = await client.get("/api/v1/misp/feed?search=%20%20", headers=admin_headers)
        assert ws_res.status_code == 200
        assert "items" in ws_res.json()

        # 2. Non-existent search returns 0 results cleanly
        empty_res = await client.get("/api/v1/misp/feed?search=NONEXISTENT_CVE_XYZ999", headers=admin_headers)
        assert empty_res.status_code == 200
        assert empty_res.json()["total"] == 0
        assert len(empty_res.json()["items"]) == 0

    @pytest.mark.asyncio
    async def test_misp_zmq_test_connection_endpoint(self, client: AsyncClient, admin_headers: dict, analyst_headers: dict):
        # 1. Non-admin must be rejected with 403
        res_analyst = await client.post("/api/v1/settings/test-misp-zmq", headers=analyst_headers, json={"host": "127.0.0.1", "port": 50000})
        assert res_analyst.status_code == 403

        # 2. Admin test with mock/local host
        res = await client.post("/api/v1/settings/test-misp-zmq", headers=admin_headers, json={"host": "127.0.0.1", "port": 50000})
        assert res.status_code == 200
        data = res.json()
        assert "success" in data
        assert "message" in data
        assert data["host"] == "127.0.0.1"
        assert data["port"] == 50000
        assert "subscriber_active" in data

    @pytest.mark.asyncio
    async def test_misp_zmq_realtime_stream_event_processing(self, client: AsyncClient, admin_headers: dict):
        import json
        from app.services.misp_zmq_subscriber import process_misp_zmq_payload
        from app.services.telegram_service import TelegramService

        sample_zmq_event = {
            "Event": {
                "id": "77777",
                "info": "FS-ISAC Live Stream Advisory: OpenSSH Remote Code Execution regreSSHion",
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

        # 1. Simulate ZeroMQ payload arrival on topic 'misp_json_event'
        await process_misp_zmq_payload("misp_json_event", json.dumps(sample_zmq_event))

        # 2. Verify alert system reflection (Alerts Center /api/v1/alerts)
        alerts_res = await client.get("/api/v1/alerts?search=CVE-2024-6387", headers=admin_headers)
        assert alerts_res.status_code == 200
        alerts_data = alerts_res.json()["items"]
        assert len(alerts_data) > 0
        matching = [a for a in alerts_data if a["cve_id"] == "CVE-2024-6387"]
        assert len(matching) > 0
        assert matching[0]["severity"] == "Critical"

        # 3. Verify Telegram message formatting for the alert
        tg_text = TelegramService.format_misp_assessment_alert(matching[0])
        assert "CVE-2024-6387" in tg_text
        assert "CRITICAL" in tg_text.upper()

        # 4. Verify audit log reflection
        audit_res = await client.get("/api/v1/audit-logs?search=CVE-2024-6387", headers=admin_headers)
        assert audit_res.status_code == 200
        actions = [l["action"] for l in audit_res.json()["items"]]
        assert "MISP_ZMQ_FEED_RECEIVED" in actions or "MISP_EVENT_TRIGGERED" in actions

        # 5. Non-FS-ISAC ZeroMQ message is safely ignored
        non_fs_isac_event = {
            "Event": {
                "id": "99999",
                "info": "Generic submission not related to FS-ISAC",
                "Orgc": {"name": "Generic-Third-Party"},
                "Tag": [{"name": "random-tag"}]
            }
        }
        await process_misp_zmq_payload("misp_json_event", json.dumps(non_fs_isac_event))
