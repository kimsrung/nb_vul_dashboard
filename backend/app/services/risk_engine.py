from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple


class RiskEngine:
    """
    Evaluates vulnerability detections based strictly on raw Qualys Severities (1 to 5).
    No synthetic composite math is applied.
    """

    @classmethod
    def count_asset_severities(
        cls,
        detections: List[Any],
    ) -> Dict[str, int]:
        """
        Count active detections across Qualys Severity 1 to 5.
        Ignores Fixed, Resolved, and False_Positive detections.
        """
        counts = {
            "total": 0,
            "sev5": 0,  # Critical
            "sev4": 0,  # High
            "sev3": 0,  # Medium
            "sev2": 0,  # Low
            "sev1": 0,  # Info
        }

        for det in detections:
            status = getattr(det, "status", None) or (det.get("status") if isinstance(det, dict) else "Active")
            if status == "Fixed":
                continue

            remediation_status = getattr(det, "remediation_status", "Open") if not isinstance(det, dict) else det.get("remediation_status", "Open")
            if remediation_status in ("Resolved", "False_Positive"):
                continue

            sev = getattr(det, "severity", 1) if not isinstance(det, dict) else det.get("severity", 1)
            try:
                sev_int = int(sev)
            except (ValueError, TypeError):
                sev_int = 1

            counts["total"] += 1
            if sev_int == 5:
                counts["sev5"] += 1
            elif sev_int == 4:
                counts["sev4"] += 1
            elif sev_int == 3:
                counts["sev3"] += 1
            elif sev_int == 2:
                counts["sev2"] += 1
            else:
                counts["sev1"] += 1

        return counts

    @classmethod
    def calculate_asset_risk(
        cls,
        detections: List[Any],
        kb_map: Dict[int, Any] | None = None,
        now: datetime | None = None,
    ) -> Tuple[float, str, bool, int, int, int]:
        """
        Calculates raw severity counts and returns:
        (risk_score=0.0, peak_level, is_risky, total, sev5_crit, sev4_high)
        """
        counts = cls.count_asset_severities(detections)

        if counts["sev5"] > 0:
            risk_level = "Critical"
            is_risky = True
        elif counts["sev4"] > 0:
            risk_level = "High"
            is_risky = True
        elif counts["sev3"] > 0:
            risk_level = "Medium"
            is_risky = False
        else:
            risk_level = "Low"
            is_risky = False

        return 0.0, risk_level, is_risky, counts["total"], counts["sev5"], counts["sev4"]
