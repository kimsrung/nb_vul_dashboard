import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase
from app.models.alert import Alert
from app.models.setting import SystemSetting
from app.services.qualys_client import QualysApiClient
from app.services.risk_engine import RiskEngine
from app.services.telegram_service import TelegramService
from app.services.audit_service import AuditService
from app.services.sync_runner import SyncRunner
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine

logger = logging.getLogger(__name__)

sync_lock = asyncio.Lock()
current_sync_status = {
    "status": "Idle",
    "last_run": None,
    "sync_mode": None,
    "message": "No sync executed yet.",
}


class SyncService:
    @classmethod
    async def get_sync_status(cls, session: Optional[AsyncSession] = None) -> Dict[str, Any]:
        if session:
            try:
                runner_status = await SyncRunner.get_sync_status(session, "qualys")
                if runner_status.get("active_job"):
                    j = runner_status["active_job"]
                    current_sync_status["status"] = "Syncing"
                    current_sync_status["sync_mode"] = j.sync_mode
                    current_sync_status["message"] = f"Qualys {j.sync_mode} sync: {j.progress_pct}% - {j.message}"
                elif runner_status.get("latest_completed_job"):
                    j = runner_status["latest_completed_job"]
                    current_sync_status["status"] = "Idle" if j.status == "completed" else "Error"
                    current_sync_status["last_run"] = j.completed_at.isoformat() if j.completed_at else None
                    current_sync_status["sync_mode"] = j.sync_mode
                    current_sync_status["message"] = j.message
            except Exception:
                pass
        return current_sync_status

    @classmethod
    async def run_sync(
        cls,
        db: AsyncSession,
        sync_mode: str = "delta",
        manual_trigger: bool = False,
        triggered_by: Optional[str] = None,
        job_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Orchestrate KnowledgeBase and Host Detection synchronization.
        Supports:
          - 'delta': Quick incremental sync querying updated detections since watermark.
          - 'full': Complete inventory reconciliation, paginating all hosts and detecting decommissioned servers.
        """
        if sync_lock.locked():
            return {"success": False, "message": "A sync job is already in progress."}

        async with sync_lock:
            if sync_mode not in ("delta", "full"):
                sync_mode = "delta"

            # Acquire persistent database-backed job lock if not already allocated
            if job_id is None:
                job, err = await SyncRunner.acquire_job(
                    session=db,
                    source="qualys",
                    sync_mode=sync_mode,
                    trigger_type="manual" if manual_trigger else "scheduled",
                    triggered_by=triggered_by,
                )
                if err:
                    return {"success": False, "message": err}
                job_id = job.id

            current_sync_status["status"] = "Syncing"
            current_sync_status["sync_mode"] = sync_mode
            current_sync_status["message"] = (
                f"Starting Qualys {'incremental delta' if sync_mode == 'delta' else 'full reconciliation'} sync..."
            )
            now = datetime.now(timezone.utc)

            try:
                await SyncRunner.update_progress(
                    job_id=job_id,
                    processed_items=0,
                    total_items=100,
                    message=f"Starting Qualys {sync_mode} sync...",
                )
                # 1. Initialize Qualys client with current DB / config settings
                settings_res = await db.execute(select(SystemSetting))
                for row in settings_res.scalars().all():
                    k, v = row.key, row.value
                    if k == "qualys_api_url" and v:
                        settings.QUALYS_API_URL = v
                    elif k == "qualys_username" and v:
                        settings.QUALYS_USERNAME = v
                    elif k == "qualys_password" and v:
                        settings.QUALYS_PASSWORD = v
                    elif k == "qualys_mock_mode":
                        settings.QUALYS_MOCK_MODE = v.lower() in ("true", "1")
                    elif k == "qualys_tag_filter":
                        settings.QUALYS_TAG_FILTER = v

                client = QualysApiClient(
                    base_url=settings.QUALYS_API_URL,
                    username=settings.QUALYS_USERNAME,
                    password=settings.QUALYS_PASSWORD,
                    mock_mode=settings.QUALYS_MOCK_MODE,
                )

                # 2. Determine delta watermark if in delta mode
                updated_since: Optional[str] = None
                if sync_mode == "delta":
                    watermark_setting = await db.get(SystemSetting, "qualys_last_sync_watermark")
                    if watermark_setting and watermark_setting.value:
                        updated_since = watermark_setting.value
                    else:
                        logger.info("No prior sync watermark found. Promoting delta sync to full reconciliation.")
                        sync_mode = "full"
                        updated_since = None

                # 3. Ingest Host Detections with auto-pagination
                current_sync_status["message"] = f"Querying Qualys Host Detection API ({sync_mode} mode)..."
                tag_filter = settings.QUALYS_TAG_FILTER if settings.QUALYS_TAG_FILTER else None
                parsed_hosts = await client.fetch_all_hosts_with_detections(
                    updated_since=updated_since,
                    tag_set_include=tag_filter,
                    status="Active,New,Re-Opened,Fixed",
                )

                total_hosts = len(parsed_hosts)
                await SyncRunner.update_progress(
                    job_id=job_id,
                    processed_items=0,
                    total_items=total_hosts or 100,
                    message=f"Fetched {total_hosts} hosts from Qualys API. Checking KnowledgeBase...",
                )

                # 4. Collect all unique QIDs present in the detections
                all_qids = set()
                for host_data in parsed_hosts:
                    for det_item in host_data.get("detections", []):
                        if det_item.get("qid"):
                            all_qids.add(det_item["qid"])

                # In mock mode, include preset mock QIDs
                if client.mock_mode:
                    all_qids.update([378291, 376241, 91942, 150682, 38914, 105822])

                # 5. Identify which QIDs need enrichment from Qualys KnowledgeBase API
                missing_qids = []
                for qid in all_qids:
                    existing = await db.get(KnowledgeBase, qid)
                    if not existing or not existing.solution:
                        missing_qids.append(qid)

                # 6. Enrich missing QIDs from Qualys KB API in targeted batches
                kb_items_added = 0
                if missing_qids:
                    current_sync_status["message"] = f"Fetching fix guidance for {len(missing_qids)} QIDs from KnowledgeBase API..."
                    await SyncRunner.update_progress(
                        job_id=job_id,
                        processed_items=0,
                        total_items=total_hosts or 100,
                        message=f"Enriching {len(missing_qids)} QIDs from Qualys KnowledgeBase API...",
                    )
                    enriched_kb_list = await client.fetch_and_parse_kb_for_qids(missing_qids)
                    for kb_data in enriched_kb_list:
                        qid = kb_data["qid"]
                        existing_kb = await db.get(KnowledgeBase, qid)
                        if existing_kb:
                            for k, v in kb_data.items():
                                setattr(existing_kb, k, v)
                            existing_kb.updated_at = now
                        else:
                            db.add(KnowledgeBase(**kb_data, created_at=now, updated_at=now))
                        kb_items_added += 1
                    await db.flush()

                # 7. Build kb_map from database
                kb_map: Dict[int, KnowledgeBase] = {}
                if all_qids:
                    kb_res = await db.execute(select(KnowledgeBase).where(KnowledgeBase.qid.in_(list(all_qids))))
                    for row in kb_res.scalars().all():
                        kb_map[row.qid] = row

                seen_qualys_ids = set()
                updated_asset_ids = set()
                assets_updated = 0
                alerts_triggered = 0
                fixed_detections_count = 0
                now = datetime.now(timezone.utc)

                for idx, host_data in enumerate(parsed_hosts, 1):
                    qualys_id = host_data["qualys_id"]
                    seen_qualys_ids.add(qualys_id)
                    detections_data = host_data.pop("detections", [])

                    # Find or create Asset
                    res = await db.execute(select(Asset).where(Asset.qualys_id == qualys_id).limit(1))
                    asset = res.scalars().first()

                    s_name = host_data.get("server_name") or (host_data.get("fqdn", "").split(".")[0] if host_data.get("fqdn") else host_data.get("netbios_name"))

                    if asset is None:
                        asset = Asset(
                            qualys_id=qualys_id,
                            server_name=s_name,
                            ip_address=host_data.get("ip_address"),
                            ipv6_address=host_data.get("ipv6_address"),
                            fqdn=host_data.get("fqdn"),
                            netbios_name=host_data.get("netbios_name"),
                            os_name=host_data.get("os_name"),
                            os_family=host_data.get("os_family"),
                            tags=host_data.get("tags", []),
                            last_scan_date=host_data.get("last_scan_date"),
                            is_active=True,
                            created_at=now,
                            updated_at=now,
                        )
                        db.add(asset)
                        await db.flush()
                    else:
                        if not asset.server_name and s_name:
                            asset.server_name = s_name
                        elif s_name and not any(k in (asset.server_name or "").upper() for k in ["DC", "DR", "SIT", "PROD", "CORE", "BANK"]):
                            asset.server_name = s_name
                        asset.ip_address = host_data.get("ip_address")
                        asset.ipv6_address = host_data.get("ipv6_address")
                        asset.fqdn = host_data.get("fqdn")
                        asset.netbios_name = host_data.get("netbios_name")
                        asset.os_name = host_data.get("os_name")
                        asset.os_family = host_data.get("os_family")
                        asset.tags = host_data.get("tags", [])
                        asset.last_scan_date = host_data.get("last_scan_date")
                        asset.is_active = True
                        asset.updated_at = now

                    # Sync Detections for this asset
                    for det_item in detections_data:
                        det_qid = det_item["qid"]
                        det_status = det_item.get("status", "Active")

                        # Verify QID exists in KB or create stub
                        if det_qid not in kb_map:
                            stub_kb = KnowledgeBase(
                                qid=det_qid,
                                title=f"Qualys QID {det_qid}",
                                severity=det_item.get("severity", 1),
                                created_at=now,
                                updated_at=now,
                            )
                            db.add(stub_kb)
                            await db.flush()
                            kb_map[det_qid] = stub_kb

                        det_port = det_item.get("port")
                        det_proto = det_item.get("protocol")

                        det_conditions = [
                            Detection.asset_id == asset.id,
                            Detection.qid == det_qid,
                        ]
                        if det_port is not None:
                            det_conditions.append(Detection.port == det_port)
                        if det_proto is not None:
                            det_conditions.append(Detection.protocol == det_proto)

                        det_res = await db.execute(
                            select(Detection).where(*det_conditions).limit(1)
                        )
                        detection = det_res.scalars().first()

                        if det_status == "Fixed":
                            if detection is not None:
                                detection.status = "Fixed"
                                if detection.remediation_status != "Resolved":
                                    detection.remediation_status = "Resolved"
                                    detection.updated_by = "Qualys Delta Sync"
                                    fixed_detections_count += 1
                                detection.last_found_date = det_item.get("last_found_date", detection.last_found_date)
                                detection.scanner_results = det_item.get("scanner_results", detection.scanner_results)
                                detection.updated_at = now
                        else:
                            if detection is None:
                                detection = Detection(
                                    asset_id=asset.id,
                                    qid=det_qid,
                                    detection_type=det_item.get("detection_type", "Confirmed"),
                                    severity=det_item.get("severity", 1),
                                    status=det_status,
                                    first_found_date=det_item.get("first_found_date"),
                                    last_found_date=det_item.get("last_found_date"),
                                    times_found=det_item.get("times_found", 1),
                                    port=det_port,
                                    protocol=det_proto,
                                    scanner_results=det_item.get("scanner_results"),
                                    remediation_status="Open",
                                    created_at=now,
                                    updated_at=now,
                                )
                                db.add(detection)
                            else:
                                detection.severity = det_item.get("severity", detection.severity)
                                detection.status = det_status
                                detection.last_found_date = det_item.get("last_found_date")
                                detection.times_found = det_item.get("times_found", detection.times_found)
                                detection.port = det_port
                                detection.protocol = det_proto
                                detection.scanner_results = det_item.get("scanner_results", detection.scanner_results)
                                if detection.remediation_status == "Resolved" and det_status in ("Active", "New", "Re-Opened"):
                                    detection.remediation_status = "Open"
                                detection.updated_at = now

                    await db.flush()

                    # Always load ALL detections for this asset to calculate cumulative risk score
                    all_asset_detections = (
                        await db.execute(select(Detection).where(Detection.asset_id == asset.id))
                    ).scalars().all()

                    counts = RiskEngine.count_asset_severities(all_asset_detections)

                    was_risky = asset.is_risky
                    asset.risk_score = 0.0
                    asset.risk_level = "Critical" if counts["sev5"] > 0 else "High" if counts["sev4"] > 0 else "Medium" if counts["sev3"] > 0 else "Low"
                    asset.is_risky = (counts["sev5"] > 0)
                    asset.total_vulns = counts["total"]
                    asset.critical_vulns = counts["sev5"]
                    asset.high_vulns = counts["sev4"]
                    asset.medium_vulns = counts["sev3"]
                    asset.low_vulns = counts["sev2"]
                    asset.info_vulns = counts["sev1"]
                    assets_updated += 1

                    # Extract installed software from all detections into AssetSoftware
                    await cls._sync_discovered_software(db, asset.id, all_asset_detections, now)

                    # In-app Alert record for Critical assets (Telegram dispatch reserved for MISP advisories)
                    if asset.is_risky:
                        cooldown_cutoff = now - timedelta(hours=settings.TELEGRAM_COOLDOWN_HOURS)
                        recent_alert_res = await db.execute(
                            select(Alert)
                            .where(Alert.asset_id == asset.id, Alert.created_at >= cooldown_cutoff)
                            .order_by(Alert.created_at.desc())
                            .limit(1)
                        )
                        recent_alert = recent_alert_res.scalars().first()

                        server_display = asset.server_name or (asset.fqdn.split(".")[0] if asset.fqdn else asset.netbios_name or "Unknown-Host")
                        alert_title = f"{server_display}: {asset.ip_address or 'Unknown IP'}"
                        alert_msg = f"has {counts['sev5']} Critical (Sev 5) and {counts['sev4']} High (Sev 4) vulnerabilities."

                        if recent_alert is None or not was_risky:
                            alert_record = Alert(
                                asset_id=asset.id,
                                alert_type="RISK_FLAGGED",
                                title=alert_title,
                                message=alert_msg,
                                severity=asset.risk_level,
                                is_resolved=False,
                                dispatched_to_telegram=False,
                                created_at=now,
                            )
                            db.add(alert_record)
                            alerts_triggered += 1

                    updated_asset_ids.add(asset.id)

                    if idx % 25 == 0 or idx == total_hosts:
                        await SyncRunner.update_progress(
                            job_id=job_id,
                            processed_items=idx,
                            total_items=total_hosts,
                            message=f"Processing host {idx}/{total_hosts} ({server_display})...",
                            details={
                                "assets_updated": assets_updated,
                                "fixed_detections": fixed_detections_count,
                            },
                        )

                # 8. Reconcile Decommissioned Assets (Only during full reconciliation)
                decommissioned_count = 0
                if sync_mode == "full" and len(seen_qualys_ids) > 0:
                    active_assets_res = await db.execute(select(Asset).where(Asset.is_active == True))
                    for a in active_assets_res.scalars().all():
                        if a.qualys_id not in seen_qualys_ids:
                            a.is_active = False
                            a.updated_at = now
                            decommissioned_count += 1
                            logger.info(
                                f"Decommissioned/Inactive host detected: '{a.server_name}' (ID: {a.id}, Qualys ID: {a.qualys_id})"
                            )

                # 9. Targeted MISP Evaluation on modified assets
                if updated_asset_ids:
                    await SyncRunner.update_progress(
                        job_id=job_id,
                        processed_items=total_hosts,
                        total_items=total_hosts,
                        message="Evaluating modified server inventory against active MISP threat advisories...",
                    )
                    try:
                        await ProactiveAssessmentEngine.evaluate_assets_against_threats(
                            db, list(updated_asset_ids)
                        )
                    except Exception as te:
                        logger.warning(f"Targeted MISP evaluation on modified assets encountered error: {te}")

                # 10. Update system settings with sync timestamps and watermark
                last_sync_str = now.isoformat()
                watermark_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

                async def set_setting(key: str, val: str, desc: str):
                    s = await db.get(SystemSetting, key)
                    if s:
                        s.value = val
                    else:
                        db.add(SystemSetting(key=key, value=val, description=desc))

                await set_setting("last_sync_time", last_sync_str, "Timestamp of last Qualys sync")
                await set_setting("qualys_last_sync_watermark", watermark_str, "Watermark for incremental delta sync")
                await set_setting("qualys_last_sync_mode", sync_mode, "Mode of last Qualys sync (delta or full)")
                if sync_mode == "full":
                    await set_setting("qualys_last_full_sync_time", last_sync_str, "Timestamp of last full Qualys reconciliation sync")

                # 11. Audit log entry
                await AuditService.log_event(
                    db=db,
                    action=f"QUALYS_{sync_mode.upper()}_SYNC",
                    target_type="SYNC",
                    target_id="qualys",
                    target_name=f"Qualys {sync_mode.capitalize()} Sync",
                    details={
                        "sync_mode": sync_mode,
                        "assets_updated": assets_updated,
                        "fixed_detections": fixed_detections_count,
                        "decommissioned_assets": decommissioned_count,
                        "kb_items_enriched": kb_items_added,
                        "alerts_triggered": alerts_triggered,
                        "manual_trigger": manual_trigger,
                    },
                )

                await db.commit()

                mode_label = "Full reconciliation" if sync_mode == "full" else "Incremental delta"
                result_msg = (
                    f"{mode_label} sync completed successfully. "
                    f"Updated {assets_updated} assets, resolved {fixed_detections_count} fixed vulnerabilities, "
                    f"decommissioned {decommissioned_count} inactive assets, enriched {kb_items_added} KB items."
                )
                current_sync_status["status"] = "Idle"
                current_sync_status["last_run"] = last_sync_str
                current_sync_status["sync_mode"] = sync_mode
                current_sync_status["message"] = result_msg

                await SyncRunner.complete_job(
                    job_id=job_id,
                    message=result_msg,
                    details={
                        "sync_mode": sync_mode,
                        "assets_updated": assets_updated,
                        "fixed_detections": fixed_detections_count,
                        "decommissioned_assets": decommissioned_count,
                        "kb_items": kb_items_added,
                        "alerts_triggered": alerts_triggered,
                        "timestamp": last_sync_str,
                    },
                )

                return {
                    "success": True,
                    "message": result_msg,
                    "sync_mode": sync_mode,
                    "assets_updated": assets_updated,
                    "fixed_detections": fixed_detections_count,
                    "decommissioned_assets": decommissioned_count,
                    "kb_items": kb_items_added,
                    "alerts_triggered": alerts_triggered,
                    "timestamp": last_sync_str,
                }

            except Exception as e:
                await db.rollback()
                err_type = type(e).__name__
                err_detail = str(e).strip()
                if not err_detail:
                    if "Timeout" in err_type:
                        err_detail = "Request timed out while connecting to Qualys API. Check network and endpoint."
                    else:
                        err_detail = "Unknown connection or authentication error"
                err_msg = f"{err_type}: {err_detail}"
                logger.error(f"Sync failed: {err_msg}", exc_info=True)
                if job_id:
                    await SyncRunner.fail_job(job_id=job_id, error_message=err_msg)
                current_sync_status["status"] = "Error"
                current_sync_status["message"] = f"Sync failed: {err_msg}"
                return {"success": False, "message": f"Sync failed: {err_msg}"}

    @classmethod
    async def _sync_discovered_software(
        cls, db: AsyncSession, asset_id: int, detections: List[Detection], now: datetime
    ):
        """Extract installed software packages and versions directly from Qualys scanner results."""
        import re
        from app.models.software import AssetSoftware

        discovered: List[Dict[str, Any]] = []

        for d in detections:
            results = d.scanner_results or ""
            if not results:
                continue

            # 1. OpenSSH: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.13"
            m = re.search(r"OpenSSH[_-]([0-9a-zA-Z._-]+)", results, re.IGNORECASE)
            if m:
                discovered.append({
                    "product_name": "openssh",
                    "vendor": "OpenBSD",
                    "version": m.group(1),
                    "package_name": "openssh-server",
                    "install_path": "/usr/sbin/sshd",
                    "port": d.port or 22,
                })

            # 2. OpenSSL: "OpenSSL 1.1.1f 31 Mar 2020" or "OpenSSL 3.0.2"
            m = re.search(r"OpenSSL\s+([0-9a-zA-Z._-]+)", results, re.IGNORECASE)
            if m:
                discovered.append({
                    "product_name": "openssl",
                    "vendor": "OpenSSL",
                    "version": m.group(1),
                    "package_name": "libssl",
                    "install_path": "/usr/lib/libssl.so",
                    "port": None,
                })

            # 3. PostgreSQL: "psql (PostgreSQL) 12.22"
            m = re.search(r"PostgreSQL\)?\s+([0-9a-zA-Z._-]+)", results, re.IGNORECASE)
            if m:
                discovered.append({
                    "product_name": "postgresql",
                    "vendor": "PostgreSQL",
                    "version": m.group(1),
                    "package_name": f"postgresql-{m.group(1).split('.')[0]}",
                    "install_path": "/usr/lib/postgresql",
                    "port": d.port or 5432,
                })

            # 4. Nginx: "nginx/1.24.0"
            m = re.search(r"nginx/([0-9a-zA-Z._-]+)", results, re.IGNORECASE)
            if m:
                discovered.append({
                    "product_name": "nginx",
                    "vendor": "F5",
                    "version": m.group(1),
                    "package_name": "nginx-core",
                    "install_path": "/usr/sbin/nginx",
                    "port": d.port or 443,
                })

            # 5. Apache: "Apache/2.4.52"
            m = re.search(r"Apache/([0-9a-zA-Z._-]+)", results, re.IGNORECASE)
            if m:
                discovered.append({
                    "product_name": "apache",
                    "vendor": "Apache",
                    "version": m.group(1),
                    "package_name": "apache2",
                    "install_path": "/usr/sbin/apache2",
                    "port": d.port or 80,
                })

            # 6. Java JARs: /app/.../spring-web-5.3.31.jar
            for jm in re.finditer(r"/([a-zA-Z0-9_-]+)-([0-9]+\.[0-9]+[a-zA-Z0-9._-]*)\.jar", results):
                p_name = jm.group(1).lower()
                p_ver = jm.group(2)
                discovered.append({
                    "product_name": p_name,
                    "vendor": "Java/Maven",
                    "version": p_ver,
                    "package_name": f"{p_name}-{p_ver}.jar",
                    "install_path": results[:100],
                    "port": d.port,
                })

            # 7. Linux packages: "traceroute  1:2.1.0-2"
            for pm in re.finditer(r"^([a-zA-Z0-9_.-]+)\s+([0-9]+:[0-9a-zA-Z._-]+|[0-9]+\.[0-9a-zA-Z._-]+)\s+", results, re.MULTILINE):
                pkg_n = pm.group(1).lower()
                if pkg_n not in ("package", "installed", "version"):
                    discovered.append({
                        "product_name": pkg_n,
                        "vendor": "System Package",
                        "version": pm.group(2),
                        "package_name": pkg_n,
                        "install_path": "/usr/bin",
                        "port": None,
                    })

        seen_keys = set()
        for sw_info in discovered:
            key = (sw_info["product_name"], sw_info["version"])
            if key in seen_keys:
                continue
            seen_keys.add(key)

            existing_sw = (
                await db.execute(
                    select(AssetSoftware).where(
                        AssetSoftware.asset_id == asset_id,
                        AssetSoftware.product_name == sw_info["product_name"],
                    ).limit(1)
                )
            ).scalars().first()

            if existing_sw:
                existing_sw.version = sw_info["version"]
                existing_sw.vendor = sw_info["vendor"]
                existing_sw.package_name = sw_info["package_name"]
                existing_sw.install_path = sw_info["install_path"]
                existing_sw.port = sw_info["port"] or existing_sw.port
                existing_sw.updated_at = now
            else:
                db.add(AssetSoftware(
                    asset_id=asset_id,
                    product_name=sw_info["product_name"],
                    vendor=sw_info["vendor"],
                    version=sw_info["version"],
                    package_name=sw_info["package_name"],
                    install_path=sw_info["install_path"],
                    port=sw_info["port"],
                    created_at=now,
                    updated_at=now,
                ))
