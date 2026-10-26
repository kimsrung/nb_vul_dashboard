import pytest
from datetime import datetime, timezone
from httpx import AsyncClient

from app.services.risk_engine import RiskEngine
from app.models.detection import Detection


class TestRiskEngineAndRemediation:
    def test_risk_engine_base_severity_scores(self):
        # Raw Qualys severities 1 to 5
        det_sev5 = Detection(qid=1001, severity=5, remediation_status="Open", first_found_date=datetime.now(timezone.utc))
        det_sev4 = Detection(qid=1002, severity=4, remediation_status="Open", first_found_date=datetime.now(timezone.utc))
        det_sev1 = Detection(qid=1003, severity=1, remediation_status="Open", first_found_date=datetime.now(timezone.utc))

        counts = RiskEngine.count_asset_severities([det_sev5, det_sev4, det_sev1])
        assert counts["sev5"] == 1
        assert counts["sev4"] == 1
        assert counts["sev1"] == 1
        assert counts["total"] == 3

    def test_resolved_and_false_positive_detections_ignored_in_risk(self):
        # Open detection counted
        det_open = Detection(qid=1002, severity=5, remediation_status="Open", first_found_date=datetime.now(timezone.utc))
        counts_open = RiskEngine.count_asset_severities([det_open])
        assert counts_open["sev5"] == 1
        assert counts_open["total"] == 1

        # Resolved detection ignored
        det_resolved = Detection(qid=1002, severity=5, remediation_status="Resolved", first_found_date=datetime.now(timezone.utc))
        counts_res = RiskEngine.count_asset_severities([det_resolved])
        assert counts_res["sev5"] == 0
        assert counts_res["total"] == 0

        # False positive ignored
        det_fp = Detection(qid=1002, severity=5, remediation_status="False_Positive", first_found_date=datetime.now(timezone.utc))
        counts_fp = RiskEngine.count_asset_severities([det_fp])
        assert counts_fp["sev5"] == 0
        assert counts_fp["total"] == 0

    @pytest.mark.asyncio
    async def test_get_detection_detail(self, client: AsyncClient, admin_headers: dict):
        # Find asset with detections
        assets_res = await client.get("/api/v1/assets?page=1&page_size=10", headers=admin_headers)
        assets = assets_res.json()["items"]
        target_det_id = None
        for a in assets:
            detail_res = await client.get(f"/api/v1/assets/{a['id']}", headers=admin_headers)
            dets = detail_res.json().get("detections", [])
            if dets:
                target_det_id = dets[0]["id"]
                break

        assert target_det_id is not None, "At least one detection should exist in seeded database"

        det_res = await client.get(f"/api/v1/detections/{target_det_id}", headers=admin_headers)
        assert det_res.status_code == 200
        det_data = det_res.json()
        assert det_data["id"] == target_det_id
        assert "remediation_status" in det_data
        assert "severity" in det_data

    @pytest.mark.asyncio
    async def test_remediation_status_update_and_asset_risk_recalculation(self, client: AsyncClient, admin_headers: dict):
        # 1. Locate an asset with a detection
        assets_res = await client.get("/api/v1/assets?page=1&page_size=10", headers=admin_headers)
        asset_id = None
        det_id = None
        for a in assets_res.json()["items"]:
            detail_res = await client.get(f"/api/v1/assets/{a['id']}", headers=admin_headers)
            dets = detail_res.json().get("detections", [])
            if dets:
                asset_id = a["id"]
                det_id = dets[0]["id"]
                break

        if not det_id:
            pytest.skip("No detection found to test remediation")

        # 2. Explicitly ensure detection is Open first and record baseline active detections count
        open_res = await client.patch(
            f"/api/v1/detections/{det_id}/remediation",
            headers=admin_headers,
            json={"remediation_status": "Open", "remediation_notes": "Baseline setup"}
        )
        assert open_res.status_code == 200
        asset_open = (await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)).json()
        total_open = asset_open["total_vulns"]

        # 3. Mark detection as Resolved
        resolved_res = await client.patch(
            f"/api/v1/detections/{det_id}/remediation",
            headers=admin_headers,
            json={"remediation_status": "Resolved", "remediation_notes": "Upgraded package in maintenance window"}
        )
        assert resolved_res.status_code == 200
        assert resolved_res.json()["remediation_status"] == "Resolved"

        # 4. Verify parent asset's active detection count decreased when detection resolved
        asset_resolved = (await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)).json()
        assert asset_resolved["total_vulns"] < total_open

        # 5. Restore back to Open
        restore_res = await client.patch(
            f"/api/v1/detections/{det_id}/remediation",
            headers=admin_headers,
            json={"remediation_status": "Open", "remediation_notes": "Reopened"}
        )
        assert restore_res.status_code == 200
        asset_restored = (await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)).json()
        assert asset_restored["total_vulns"] == total_open

    @pytest.mark.asyncio
    async def test_remediation_invalid_status_rejected(self, client: AsyncClient, admin_headers: dict):
        res = await client.patch("/api/v1/detections/1/remediation", headers=admin_headers, json={"remediation_status": "InvalidStatus"})
        assert res.status_code == 400

    def test_risk_engine_empty_detections_edge_case(self):
        # Clean host with zero detections
        counts = RiskEngine.count_asset_severities([])
        assert counts["sev5"] == 0
        assert counts["sev4"] == 0
        assert counts["sev3"] == 0
        assert counts["sev2"] == 0
        assert counts["sev1"] == 0
        assert counts["total"] == 0

    @pytest.mark.asyncio
    async def test_get_knowledge_base_detail(self, client: AsyncClient, admin_headers: dict):
        # Locate an existing detection to get its QID
        assets_res = await client.get("/api/v1/assets?page=1&page_size=5", headers=admin_headers)
        qid = None
        for a in assets_res.json()["items"]:
            detail_res = await client.get(f"/api/v1/assets/{a['id']}", headers=admin_headers)
            dets = detail_res.json().get("detections", [])
            if dets:
                qid = dets[0]["qid"]
                break

        assert qid is not None, "At least one QID should be present in seeded database"

        kb_res = await client.get(f"/api/v1/kb/{qid}", headers=admin_headers)
        assert kb_res.status_code == 200
        kb = kb_res.json()
        assert kb["qid"] == qid
        assert "title" in kb
        assert "solution" in kb
        assert "category" in kb

    @pytest.mark.asyncio
    async def test_get_knowledge_base_not_found_edge_case(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/kb/99999999", headers=admin_headers)
        assert res.status_code == 404
        assert "not found in local KnowledgeBase cache" in res.json()["detail"]
