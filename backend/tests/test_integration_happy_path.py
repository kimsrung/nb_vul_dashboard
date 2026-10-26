import pytest
from httpx import AsyncClient


class TestEndToEndHappyPathIntegration:
    """
    Comprehensive End-to-End Happy Path Integration Test.
    Exercises the complete security operations lifecycle:
    1. Authentication & RBAC token retrieval
    2. Qualys sync & host inventory ingestion (Severities 1-5)
    3. MISP FS-ISAC advisory ingestion & proactive pre-scan inventory matching
    4. Alert Center triage & filtering (strictly affecting infrastructure)
    5. KnowledgeBase diagnostic retrieval & remediation status update
    6. Automatic parent asset severity counter recalculation
    7. Threat alert resolution & audit trail verification
    8. Executive Dashboard summary KPI reconciliation
    """

    @pytest.mark.asyncio
    async def test_full_platform_happy_path_lifecycle(
        self,
        client: AsyncClient,
        admin_headers: dict,
        analyst_headers: dict,
    ):
        # =========================================================================
        # Stage 1: Authentication & RBAC Verification
        # =========================================================================
        # 1.1 Verify Admin profile
        me_res = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert me_res.status_code == 200
        admin_profile = me_res.json()
        assert admin_profile["username"] == "admin"
        assert admin_profile["role"] == "admin"
        assert admin_profile["is_active"] is True

        # 1.2 Verify Analyst profile
        analyst_me = await client.get("/api/v1/auth/me", headers=analyst_headers)
        assert analyst_me.status_code == 200
        assert analyst_me.json()["role"] == "analyst"

        # =========================================================================
        # Stage 2: Qualys Scan Sync & Asset Ingestion
        # =========================================================================
        # 2.1 Trigger Qualys Delta Sync
        sync_res = await client.post("/api/v1/dashboard/sync?mode=delta", headers=admin_headers)
        assert sync_res.status_code == 200
        assert sync_res.json()["success"] is True

        # 2.2 Verify sync status is healthy
        status_res = await client.get("/api/v1/dashboard/sync-status", headers=admin_headers)
        assert status_res.status_code == 200

        # 2.3 Query Host Inventory
        assets_res = await client.get("/api/v1/assets?page=1&page_size=20", headers=admin_headers)
        assert assets_res.status_code == 200
        assets_data = assets_res.json()
        assert assets_data["total"] > 0
        assert len(assets_data["items"]) > 0

        first_asset = assets_data["items"][0]
        assert "server_name" in first_asset
        assert "ip_address" in first_asset
        assert "os_family" in first_asset
        assert "risk_level" in first_asset
        assert "critical_vulns" in first_asset
        assert "high_vulns" in first_asset
        assert "total_vulns" in first_asset

        # =========================================================================
        # Stage 3: MISP FS-ISAC Ingestion & Pre-Scan Inventory Matching
        # =========================================================================
        # 3.1 Trigger MISP FS-ISAC feed synchronization
        misp_sync_res = await client.post("/api/v1/misp/sync", headers=admin_headers)
        assert misp_sync_res.status_code == 200
        sync_payload = misp_sync_res.json()
        assert sync_payload["success"] is True
        assert sync_payload["assessments_run"] > 0

        # 3.2 Verify MISP Feed listing contains consolidated unique CVEs with MISP metadata
        feed_res = await client.get("/api/v1/misp/feed?page=1&page_size=10", headers=admin_headers)
        assert feed_res.status_code == 200
        feed_data = feed_res.json()
        assert feed_data["total"] > 0
        assert "total_events" in feed_data

        sample_cve = feed_data["items"][0]
        assert "cve_id" in sample_cve
        assert "misp_event_id" in sample_cve
        assert "misp_event_date" in sample_cve
        assert "created_at" in sample_cve
        assert "affected_product" in sample_cve
        assert "match_type" in sample_cve

        # 3.3 Verify MISP Summary KPI counts
        misp_summary_res = await client.get("/api/v1/misp/summary", headers=admin_headers)
        assert misp_summary_res.status_code == 200
        misp_sum = misp_summary_res.json()
        assert misp_sum["total_advisories"] > 0
        assert misp_sum["pre_scan_matches"] >= 0

        # =========================================================================
        # Stage 4: Alert Center Triage & Inventory Correlation
        # =========================================================================
        # 4.1 Retrieve active threat alerts (strictly affecting host inventory)
        alerts_res = await client.get("/api/v1/alerts?page=1&page_size=10", headers=admin_headers)
        assert alerts_res.status_code == 200
        alerts_data = alerts_res.json()
        assert alerts_data["total"] > 0

        # Every alert in the alert center must have affected monitored assets
        for alert in alerts_data["items"]:
            assert len(alert["affected_assets"]) > 0
            assert alert["severity"] in ("Critical", "High", "Medium", "Low", "Info")

        # 4.2 Verify severity filtering
        crit_alerts_res = await client.get("/api/v1/alerts?severity=Critical", headers=admin_headers)
        assert crit_alerts_res.status_code == 200
        for item in crit_alerts_res.json()["items"]:
            assert item["severity"] == "Critical"

        # =========================================================================
        # Stage 5: KnowledgeBase Guidance & Automatic Severity Recalculation
        # =========================================================================
        # 5.1 Find an asset with active detections
        target_asset_id = None
        target_detection_id = None
        target_qid = None

        for a in assets_data["items"]:
            detail_res = await client.get(f"/api/v1/assets/{a['id']}", headers=admin_headers)
            dets = detail_res.json().get("detections", [])
            active_dets = [d for d in dets if d.get("remediation_status") not in ("Resolved", "False_Positive")]
            if active_dets:
                target_asset_id = a["id"]
                target_detection_id = active_dets[0]["id"]
                target_qid = active_dets[0]["qid"]
                break

        assert target_asset_id is not None, "Expected at least one asset with active detections"

        # 5.2 Retrieve KnowledgeBase enrichment for the detection
        kb_res = await client.get(f"/api/v1/kb/{target_qid}", headers=admin_headers)
        assert kb_res.status_code == 200
        kb_data = kb_res.json()
        assert kb_data["qid"] == target_qid
        assert "title" in kb_data
        assert "solution" in kb_data

        # 5.3 Fetch current asset active detection count before remediation
        asset_before = (await client.get(f"/api/v1/assets/{target_asset_id}", headers=admin_headers)).json()
        total_vulns_before = asset_before["total_vulns"]

        # 5.4 Update remediation status to 'Resolved'
        remediation_res = await client.patch(
            f"/api/v1/detections/{target_detection_id}/remediation",
            headers=admin_headers,
            json={
                "remediation_status": "Resolved",
                "remediation_notes": "Security patch applied and service restarted by SecOps.",
            },
        )
        assert remediation_res.status_code == 200
        assert remediation_res.json()["remediation_status"] == "Resolved"

        # 5.5 Verify parent asset's active severities were automatically recalculated
        asset_after = (await client.get(f"/api/v1/assets/{target_asset_id}", headers=admin_headers)).json()
        assert asset_after["total_vulns"] == total_vulns_before - 1

        # =========================================================================
        # Stage 6: Threat Alert Resolution & Audit Trail
        # =========================================================================
        # 6.1 Pick an unresolved alert to resolve
        sample_alert = alerts_data["items"][0]
        alert_id = sample_alert["id"]

        resolve_res = await client.post(
            f"/api/v1/alerts/{alert_id}/resolve",
            headers=admin_headers,
            json={
                "status": "Remediated",
                "resolution_notes": "Emergency CVE mitigations verified on server cluster.",
            },
        )
        assert resolve_res.status_code == 200
        assert resolve_res.json()["is_resolved"] is True
        assert resolve_res.json()["status"] == "Remediated"

        # 6.2 Verify an Audit Log was recorded
        audit_res = await client.get("/api/v1/audit-logs?page=1&page_size=5", headers=admin_headers)
        assert audit_res.status_code == 200
        audit_entries = audit_res.json()["items"]
        assert len(audit_entries) > 0
        assert any(entry["actor_username"] == "admin" for entry in audit_entries)

        # =========================================================================
        # Stage 7: Executive Dashboard Summary KPI Reconciliation
        # =========================================================================
        dash_res = await client.get("/api/v1/dashboard/summary", headers=admin_headers)
        assert dash_res.status_code == 200
        dash_data = dash_res.json()

        assert "total_assets" in dash_data
        assert "risky_assets" in dash_data
        assert "total_vulns" in dash_data
        assert "critical_vulns" in dash_data
        assert "high_vulns" in dash_data
        assert "active_alerts" in dash_data
        assert "misp_advisories_count" in dash_data
        assert "misp_matched_assets_count" in dash_data

        # Verify logical relationships
        assert dash_data["total_assets"] >= dash_data["risky_assets"]
        assert dash_data["total_vulns"] >= (dash_data["critical_vulns"] + dash_data["high_vulns"])
