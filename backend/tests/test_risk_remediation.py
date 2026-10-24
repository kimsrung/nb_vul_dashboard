import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.services.risk_engine import RiskEngine
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase


class TestRiskEngineAndRemediation:
    def test_risk_engine_base_severity_scores(self):
        # Severity 1=2.0, 2=5.0, 3=12.0, 4=25.0, 5=45.0
        kb = KnowledgeBase(qid=1001, threat_intel_flags={})
        det_sev5 = Detection(qid=1001, severity=5, remediation_status="Open", first_found_date=datetime.now(timezone.utc))
        det_sev4 = Detection(qid=1001, severity=4, remediation_status="Open", first_found_date=datetime.now(timezone.utc))
        det_sev1 = Detection(qid=1001, severity=1, remediation_status="Open", first_found_date=datetime.now(timezone.utc))

        kb_map = {1001: kb}
        score5, lvl5, _, _, _, _ = RiskEngine.calculate_asset_risk([det_sev5], kb_map)
        score4, lvl4, _, _, _, _ = RiskEngine.calculate_asset_risk([det_sev4], kb_map)
        score1, lvl1, _, _, _, _ = RiskEngine.calculate_asset_risk([det_sev1], kb_map)

        assert score5 > score4 > score1
        assert lvl5 in ("Critical", "High", "Medium", "Low")

    def test_resolved_and_false_positive_detections_ignored_in_risk(self):
        kb = KnowledgeBase(qid=1002, threat_intel_flags={"ransomware": True})
        kb_map = {1002: kb}

        # Open detection has positive risk
        det_open = Detection(qid=1002, severity=5, remediation_status="Open", first_found_date=datetime.now(timezone.utc))
        score_open, _, is_risky_open, total_open, crit_open, _ = RiskEngine.calculate_asset_risk([det_open], kb_map)
        assert score_open > 0
        assert is_risky_open is True
        assert total_open == 1
        assert crit_open == 1

        # Resolved detection has 0.0 risk
        det_resolved = Detection(qid=1002, severity=5, remediation_status="Resolved", first_found_date=datetime.now(timezone.utc))
        score_resolved, lvl_resolved, is_risky_resolved, total_res, crit_res, _ = RiskEngine.calculate_asset_risk([det_resolved], kb_map)
        assert score_resolved == 0.0
        assert lvl_resolved == "Low"
        assert is_risky_resolved is False
        assert total_res == 0
        assert crit_res == 0

        # False positive has 0.0 risk
        det_fp = Detection(qid=1002, severity=5, remediation_status="False_Positive", first_found_date=datetime.now(timezone.utc))
        score_fp, lvl_fp, is_risky_fp, _, _, _ = RiskEngine.calculate_asset_risk([det_fp], kb_map)
        assert score_fp == 0.0
        assert lvl_fp == "Low"
        assert is_risky_fp is False

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

        # 2. Explicitly ensure detection is Open first and record baseline score
        open_res = await client.patch(
            f"/api/v1/detections/{det_id}/remediation",
            headers=admin_headers,
            json={"remediation_status": "Open", "remediation_notes": "Baseline setup"}
        )
        assert open_res.status_code == 200
        asset_open = (await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)).json()
        score_open = asset_open["risk_score"]

        # 3. Mark detection as Resolved
        resolved_res = await client.patch(
            f"/api/v1/detections/{det_id}/remediation",
            headers=admin_headers,
            json={"remediation_status": "Resolved", "remediation_notes": "Upgraded package in maintenance window"}
        )
        assert resolved_res.status_code == 200
        assert resolved_res.json()["remediation_status"] == "Resolved"

        # 4. Verify parent asset's risk score decreased when detection resolved
        asset_resolved = (await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)).json()
        score_resolved = asset_resolved["risk_score"]
        assert score_resolved < score_open

        # 5. Restore back to Open
        restore_res = await client.patch(
            f"/api/v1/detections/{det_id}/remediation",
            headers=admin_headers,
            json={"remediation_status": "Open", "remediation_notes": "Reopened"}
        )
        assert restore_res.status_code == 200
        asset_restored = (await client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)).json()
        assert asset_restored["risk_score"] == score_open

    @pytest.mark.asyncio
    async def test_remediation_invalid_status_rejected(self, client: AsyncClient, admin_headers: dict):
        res = await client.patch("/api/v1/detections/1/remediation", headers=admin_headers, json={"remediation_status": "InvalidStatus"})
        assert res.status_code == 400
        assert "Invalid remediation status" in res.json()["detail"]
