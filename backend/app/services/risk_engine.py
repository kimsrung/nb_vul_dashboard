from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from app.core.config import settings


class RiskEngine:
    SEVERITY_WEIGHTS = {
        5: 40.0,
        4: 20.0,
        3: 5.0,
        2: 2.0,
        1: 0.5,
    }

    @classmethod
    def calculate_asset_risk(
        cls,
        detections: List[Any],
        kb_map: Dict[int, Any],
        now: datetime | None = None,
    ) -> Tuple[float, str, bool, int, int, int]:
        """
        Calculate composite risk score, risk level, and vulnerability stats for an asset.
        
        Returns:
            Tuple[risk_score, risk_level, is_risky, total_vulns, critical_vulns, high_vulns]
        """
        if now is None:
            now = datetime.now(timezone.utc)

        total_score = 0.0
        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0
        has_critical_rti = False
        has_sla_breach = False

        for det in detections:
            # Only count active, new, or re-opened detections
            status = getattr(det, "status", None) or (det.get("status") if isinstance(det, dict) else "Active")
            if status == "Fixed":
                continue

            remediation_status = getattr(det, "remediation_status", "Open") if not isinstance(det, dict) else det.get("remediation_status", "Open")
            if remediation_status in ("Resolved", "False_Positive"):
                continue

            sev = getattr(det, "severity", 1) if not isinstance(det, dict) else det.get("severity", 1)
            qid = getattr(det, "qid", None) if not isinstance(det, dict) else det.get("qid")
            first_found = getattr(det, "first_found_date", None) if not isinstance(det, dict) else det.get("first_found_date")

            total_vulns += 1
            if sev == 5:
                critical_vulns += 1
            elif sev == 4:
                high_vulns += 1

            # Base severity weight
            base_weight = cls.SEVERITY_WEIGHTS.get(sev, 1.0)

            # RTI Multiplier
            kb_item = kb_map.get(qid)
            rti_multiplier = 1.0
            if kb_item:
                ti_flags = getattr(kb_item, "threat_intel_flags", {}) if not isinstance(kb_item, dict) else kb_item.get("threat_intel_flags", {})
                if ti_flags:
                    if ti_flags.get("ransomware"):
                        rti_multiplier = max(rti_multiplier, 2.0)
                        if sev >= 4:
                            has_critical_rti = True
                    if ti_flags.get("active_in_wild") or ti_flags.get("exploit_in_wild"):
                        rti_multiplier = max(rti_multiplier, 1.8)
                        if sev >= 4:
                            has_critical_rti = True
                    if ti_flags.get("remote_code_execution"):
                        rti_multiplier = max(rti_multiplier, 1.5)
                    if ti_flags.get("exploit_public"):
                        rti_multiplier = max(rti_multiplier, 1.4)
                    if ti_flags.get("zero_day"):
                        rti_multiplier = max(rti_multiplier, 2.0)
                        if sev >= 4:
                            has_critical_rti = True

            # SLA Age Multiplier
            sla_multiplier = 1.0
            if first_found:
                if first_found.tzinfo is None:
                    first_found = first_found.replace(tzinfo=timezone.utc)
                age_days = (now - first_found).total_seconds() / 86400.0

                if sev == 5 and age_days > settings.SLA_CRITICAL_DAYS:
                    sla_multiplier = 1.5
                    has_sla_breach = True
                elif sev == 4 and age_days > settings.SLA_HIGH_DAYS:
                    sla_multiplier = 1.3
                    has_sla_breach = True

            # Remediation acknowledgment reduction
            remediation_multiplier = 0.5 if remediation_status == "Acknowledged" else 1.0

            vuln_score = base_weight * rti_multiplier * sla_multiplier * remediation_multiplier
            total_score += vuln_score

        rounded_score = round(total_score, 1)

        # Determine Risk Level and Flagging
        if rounded_score >= settings.RISK_THRESHOLD_CRITICAL or has_critical_rti:
            risk_level = "Critical"
            is_risky = True
        elif rounded_score >= settings.RISK_THRESHOLD_HIGH or has_sla_breach or critical_vulns > 0:
            risk_level = "High"
            is_risky = True
        elif rounded_score >= 15.0 or high_vulns > 0:
            risk_level = "Medium"
            is_risky = False
        else:
            risk_level = "Low"
            is_risky = False

        return rounded_score, risk_level, is_risky, total_vulns, critical_vulns, high_vulns
