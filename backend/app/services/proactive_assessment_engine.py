import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase
from app.models.software import AssetSoftware
from app.models.misp_feed import MispCveAssessment
from app.services.telegram_service import TelegramService
from app.core.config import settings

logger = logging.getLogger(__name__)


def parse_ver(v_str: str) -> List[Tuple[int, Any]]:
    """Parse software version string into comparable tuples (handling letters like '8.9p1')."""
    if not v_str:
        return [(0, 0)]
    parts = re.findall(r"\d+|[a-zA-Z]+", str(v_str).strip())
    parsed = []
    for p in parts:
        if p.isdigit():
            parsed.append((0, int(p)))
        else:
            parsed.append((1, p.lower()))
    return parsed or [(0, 0)]


def ver_cmp(v1: str, v2: str) -> int:
    """Compare two version strings: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
    p1 = parse_ver(v1)
    p2 = parse_ver(v2)
    max_len = max(len(p1), len(p2))
    p1 += [(0, 0)] * (max_len - len(p1))
    p2 += [(0, 0)] * (max_len - len(p2))
    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def is_version_vulnerable(installed_version: str, vulnerable_expression: str) -> bool:
    """Check if an installed version matches a vulnerable expression.
    Supports: '< 9.8p1', '<= 1.25.2', '>= 1.24.0, < 1.25.3', '5.6.0, 5.6.1'.
    """
    if not installed_version or not vulnerable_expression:
        return False

    clauses = [c.strip() for c in vulnerable_expression.split(",") if c.strip()]
    if not clauses:
        return False

    # Exact version list check: '5.6.0, 5.6.1'
    if all(not any(c.startswith(op) for op in ("<", ">", "=")) for c in clauses):
        return any(installed_version.strip().startswith(c) for c in clauses)

    for clause in clauses:
        if clause.startswith("<="):
            target = clause[2:].strip()
            if ver_cmp(installed_version, target) > 0:
                return False
        elif clause.startswith("<"):
            target = clause[1:].strip()
            if ver_cmp(installed_version, target) >= 0:
                return False
        elif clause.startswith(">="):
            target = clause[2:].strip()
            if ver_cmp(installed_version, target) < 0:
                return False
        elif clause.startswith(">"):
            target = clause[1:].strip()
            if ver_cmp(installed_version, target) <= 0:
                return False
        elif clause.startswith("="):
            target = clause[1:].strip()
            if ver_cmp(installed_version, target) != 0:
                return False
    return True


# Product alias mapping for flexible inventory matching
PRODUCT_ALIASES: Dict[str, List[str]] = {
    "openssh": ["openssh", "sshd", "openssh-server", "openssh-client", "ssh"],
    "nginx": ["nginx", "nginx-core", "nginx-common", "nginx-full"],
    "xz-utils": ["xz", "xz-utils", "liblzma", "liblzma5"],
    "php": ["php", "php-cgi", "php-fpm", "php-cli", "php8"],
    "runc": ["runc", "containerd", "docker-runc"],
    "log4j": ["log4j", "log4j-core", "apache-log4j"],
    "openssl": ["openssl", "libssl", "libssl3", "libcrypto"],
    "postgresql": ["postgresql", "postgres", "psql"],
}


class ProactiveAssessmentEngine:
    """Evaluates newly published CVEs against Qualys detections and server software inventory."""

    @classmethod
    async def assess_cve(cls, db: AsyncSession, advisory: Dict[str, Any]) -> MispCveAssessment:
        """Run the full proactive assessment workflow for a single FS-ISAC CVE advisory."""
        cve_id = advisory["cve_id"].strip().upper()
        product = advisory.get("affected_product", "").lower().strip()
        vuln_versions = advisory.get("vulnerable_versions", "").strip()
        verification_cmd = advisory.get("verification_command", f"# Verify {product} version")
        now = datetime.now(timezone.utc)

        logger.info(f"Assessing FS-ISAC advisory: {cve_id} ({product} {vuln_versions})")

        # =========================================================================
        # STEP 1: Check Qualys findings (Has Qualys already scanned & detected this?)
        # =========================================================================
        qualys_matches = await cls._check_qualys_detections(db, cve_id)

        affected_assets_data: List[Dict[str, Any]] = []
        match_type = "NO_ASSETS_AFFECTED"
        confidence = "None"
        matched_qid = None

        if qualys_matches:
            match_type = "QUALYS_CONFIRMED"
            confidence = "High (Scanner Verified)"
            for asset, det, kb in qualys_matches:
                matched_qid = det.qid
                evidence_text = det.scanner_results or f"Qualys Scanner confirmed active detection for QID {det.qid}"
                affected_assets_data.append({
                    "asset_id": asset.id,
                    "server_name": asset.server_name or asset.fqdn or asset.ip_address,
                    "ip_address": asset.ip_address,
                    "os_name": asset.os_name,
                    "evidence": f"Qualys Scanner QID {det.qid}: {evidence_text}",
                    "installed_version": "Scanner Confirmed",
                    "confidence": "High",
                    "recommended_verification": f"Qualys active detection on port {det.port or 'default'}. Apply vendor patch: {kb.solution or 'Vendor patch required'}",
                })

        # =========================================================================
        # STEP 2: If NOT detected by Qualys, run proactive inventory-based assessment
        # =========================================================================
        if not affected_assets_data:
            inventory_matches = await cls._check_inventory_software(db, product, vuln_versions)
            if inventory_matches:
                match_type = "INVENTORY_PROACTIVE"
                confidence = "High"
                for asset, sw in inventory_matches:
                    port_str = f" (listening on port {sw.port})" if sw.port else ""
                    evidence_text = f"Installed package '{sw.package_name or sw.product_name}' v{sw.version} at {sw.install_path or 'system path'}{port_str}"
                    affected_assets_data.append({
                        "asset_id": asset.id,
                        "server_name": asset.server_name or asset.fqdn or asset.ip_address,
                        "ip_address": asset.ip_address,
                        "os_name": asset.os_name,
                        "evidence": evidence_text,
                        "installed_version": sw.version,
                        "confidence": "High",
                        "recommended_verification": verification_cmd,
                    })

        # Generate summary description
        if match_type == "QUALYS_CONFIRMED":
            summary = f"Qualys Scanner has already confirmed active detection of {cve_id} across {len(affected_assets_data)} server(s)."
        elif match_type == "INVENTORY_PROACTIVE":
            summary = f"Proactive pre-scan evaluation identified {len(affected_assets_data)} server(s) running vulnerable software '{product}' matching criteria '{vuln_versions}' before Qualys detection."
        else:
            summary = f"Assessment complete: No servers in the inventory are running vulnerable software matching {cve_id} ({product} {vuln_versions})."

        report_data = {
            "summary": summary,
            "affected_assets": affected_assets_data,
            "recommended_actions": advisory.get("recommended_actions", "Apply security patches or upgrade affected software package."),
            "verification_command": verification_cmd,
            "matched_qid": matched_qid,
            "vulnerable_versions": vuln_versions,
            "affected_product": product,
        }

        # Check existing record in DB
        existing_res = await db.execute(select(MispCveAssessment).where(MispCveAssessment.cve_id == cve_id).limit(1))
        record = existing_res.scalars().first()

        dispatched_now = False
        if record is None:
            record = MispCveAssessment(
                cve_id=cve_id,
                source="FS-ISAC",
                title=advisory.get("title", f"FS-ISAC Advisory {cve_id}"),
                description=advisory.get("description", ""),
                severity=advisory.get("severity", "High"),
                cvss_score=advisory.get("cvss_score"),
                affected_product=product,
                vulnerable_versions=vuln_versions,
                fixed_versions=advisory.get("fixed_versions"),
                match_type=match_type,
                confidence=confidence,
                affected_assets_count=len(affected_assets_data),
                assessment_report=report_data,
                dispatched_telegram=False,
                status="Pending",
                created_at=now,
                updated_at=now,
            )
            db.add(record)
            await db.flush()
        else:
            record.match_type = match_type
            record.confidence = confidence
            record.affected_assets_count = len(affected_assets_data)
            record.assessment_report = report_data
            record.severity = advisory.get("severity", record.severity)
            record.cvss_score = advisory.get("cvss_score", record.cvss_score)
            record.updated_at = now

        # =========================================================================
        # STEP 3: Dispatch Telegram Alert for affected servers
        # =========================================================================
        if len(affected_assets_data) > 0 and (not record.dispatched_telegram or settings.TELEGRAM_ENABLED):
            tg_text = TelegramService.format_misp_assessment_alert(record)
            tg_result = await TelegramService.send_message(tg_text)
            if tg_result.get("success"):
                record.dispatched_telegram = True
                record.telegram_sent_at = now
                dispatched_now = True

        await db.commit()
        await db.refresh(record)
        return record

    @classmethod
    async def _check_qualys_detections(cls, db: AsyncSession, cve_id: str) -> List[Tuple[Asset, Detection, KnowledgeBase]]:
        """Query existing Qualys detections mapped to this CVE."""
        # Find KnowledgeBase entries containing this CVE
        kb_query = select(KnowledgeBase)
        kb_res = await db.execute(kb_query)
        all_kb = kb_res.scalars().all()

        matching_qids: Dict[int, KnowledgeBase] = {}
        for kb in all_kb:
            if kb.cve_list and cve_id in [c.upper() for c in kb.cve_list]:
                matching_qids[kb.qid] = kb

        if not matching_qids:
            return []

        # Find active detections
        det_query = (
            select(Detection)
            .options(selectinload(Detection.asset))
            .where(
                Detection.qid.in_(list(matching_qids.keys())),
                Detection.status.in_(["Active", "Re-Opened", "New"]),
                Detection.remediation_status.not_in(["Resolved", "False_Positive"]),
            )
        )
        det_res = await db.execute(det_query)
        detections = det_res.scalars().all()

        results = []
        for d in detections:
            if d.asset:
                results.append((d.asset, d, matching_qids[d.qid]))
        return results

    @classmethod
    async def _check_inventory_software(
        cls, db: AsyncSession, product: str, vuln_versions: str
    ) -> List[Tuple[Asset, AssetSoftware]]:
        """Match product name and version against the AssetSoftware table."""
        if not product:
            return []

        # Expand product search aliases
        search_terms = PRODUCT_ALIASES.get(product.lower(), [product.lower()])

        # Query all software items matching aliases
        conditions = []
        for term in search_terms:
            conditions.append(AssetSoftware.product_name.ilike(f"%{term}%"))
            conditions.append(AssetSoftware.package_name.ilike(f"%{term}%"))

        query = select(AssetSoftware).options(selectinload(AssetSoftware.asset)).where(or_(*conditions))
        res = await db.execute(query)
        software_items = res.scalars().all()

        matches = []
        for sw in software_items:
            if sw.asset:
                # Compare version
                if is_version_vulnerable(sw.version, vuln_versions):
                    matches.append((sw.asset, sw))
        return matches
