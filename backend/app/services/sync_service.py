import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from sqlalchemy import select, update
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

logger = logging.getLogger(__name__)

sync_lock = asyncio.Lock()
current_sync_status = {"status": "Idle", "last_run": None, "message": "No sync executed yet."}


class SyncService:
    @classmethod
    async def get_sync_status(cls) -> Dict[str, Any]:
        return current_sync_status

    @classmethod
    async def run_sync(cls, db: AsyncSession, manual_trigger: bool = False) -> Dict[str, Any]:
        """Orchestrate KnowledgeBase and Host Detection synchronization."""
        if sync_lock.locked():
            return {"success": False, "message": "A sync job is already in progress."}

        async with sync_lock:
            current_sync_status["status"] = "Syncing"
            current_sync_status["message"] = "Fetching Qualys KnowledgeBase..."
            now = datetime.now(timezone.utc)

            try:
                # 1. Initialize Qualys client with current DB / config settings
                client = QualysApiClient()

                # 2. Sync KnowledgeBase
                kb_xml = await client.fetch_knowledge_base_xml()
                parsed_kb_list = client.parse_knowledge_base_xml(kb_xml)
                
                kb_map: Dict[int, KnowledgeBase] = {}
                for kb_data in parsed_kb_list:
                    qid = kb_data["qid"]
                    existing_kb = await db.get(KnowledgeBase, qid)
                    if existing_kb:
                        for k, v in kb_data.items():
                            setattr(existing_kb, k, v)
                        existing_kb.updated_at = now
                        kb_map[qid] = existing_kb
                    else:
                        new_kb = KnowledgeBase(**kb_data, created_at=now, updated_at=now)
                        db.add(new_kb)
                        kb_map[qid] = new_kb
                
                await db.flush()

                # Also load existing KB entries into map
                kb_res = await db.execute(select(KnowledgeBase))
                for row in kb_res.scalars().all():
                    kb_map[row.qid] = row

                # 3. Sync Host Detections
                current_sync_status["message"] = "Fetching Qualys Host Detections..."
                tag_filter = settings.QUALYS_TAG_FILTER if settings.QUALYS_TAG_FILTER else None
                hosts_xml = await client.fetch_host_detections_xml(tag_set_include=tag_filter)
                parsed_hosts = client.parse_host_detections_xml(hosts_xml)

                assets_updated = 0
                alerts_triggered = 0
                now = datetime.now(timezone.utc)

                for host_data in parsed_hosts:
                    qualys_id = host_data["qualys_id"]
                    detections_data = host_data.pop("detections", [])

                    # Find or create Asset
                    res = await db.execute(select(Asset).where(Asset.qualys_id == qualys_id))
                    asset = res.scalar_one_or_none()

                    if asset is None:
                        asset = Asset(
                            qualys_id=qualys_id,
                            ip_address=host_data.get("ip_address"),
                            ipv6_address=host_data.get("ipv6_address"),
                            fqdn=host_data.get("fqdn"),
                            netbios_name=host_data.get("netbios_name"),
                            os_name=host_data.get("os_name"),
                            os_family=host_data.get("os_family"),
                            tags=host_data.get("tags", []),
                            last_scan_date=host_data.get("last_scan_date"),
                            created_at=now,
                            updated_at=now,
                        )
                        db.add(asset)
                        await db.flush()
                    else:
                        asset.ip_address = host_data.get("ip_address")
                        asset.ipv6_address = host_data.get("ipv6_address")
                        asset.fqdn = host_data.get("fqdn")
                        asset.netbios_name = host_data.get("netbios_name")
                        asset.os_name = host_data.get("os_name")
                        asset.os_family = host_data.get("os_family")
                        asset.tags = host_data.get("tags", [])
                        asset.last_scan_date = host_data.get("last_scan_date")
                        asset.updated_at = now

                    # Sync Detections for this asset
                    active_detections = []
                    for det_item in detections_data:
                        det_qid = det_item["qid"]
                        # Verify QID exists in KB or create stub
                        if det_qid not in kb_map:
                            stub_kb = KnowledgeBase(
                                qid=det_qid,
                                title=f"Qualys QID {det_qid}",
                                severity=det_item["severity"],
                                created_at=now,
                                updated_at=now,
                            )
                            db.add(stub_kb)
                            await db.flush()
                            kb_map[det_qid] = stub_kb

                        det_res = await db.execute(
                            select(Detection).where(
                                Detection.asset_id == asset.id,
                                Detection.qid == det_qid,
                            )
                        )
                        detection = det_res.scalar_one_or_none()

                        if detection is None:
                            detection = Detection(
                                asset_id=asset.id,
                                qid=det_qid,
                                detection_type=det_item.get("detection_type", "Confirmed"),
                                severity=det_item.get("severity", 1),
                                status=det_item.get("status", "Active"),
                                first_found_date=det_item.get("first_found_date"),
                                last_found_date=det_item.get("last_found_date"),
                                times_found=det_item.get("times_found", 1),
                                port=det_item.get("port"),
                                protocol=det_item.get("protocol"),
                                scanner_results=det_item.get("scanner_results"),
                                remediation_status="Open",
                                created_at=now,
                                updated_at=now,
                            )
                            db.add(detection)
                        else:
                            detection.severity = det_item.get("severity", detection.severity)
                            detection.status = det_item.get("status", detection.status)
                            detection.last_found_date = det_item.get("last_found_date")
                            detection.times_found = det_item.get("times_found", detection.times_found)
                            detection.port = det_item.get("port")
                            detection.protocol = det_item.get("protocol")
                            detection.scanner_results = det_item.get("scanner_results", detection.scanner_results)
                            detection.updated_at = now
                        
                        active_detections.append(detection)

                    await db.flush()

                    # Calculate Risk Score and Counts
                    score, risk_lvl, is_risky, total_v, crit_v, high_v = RiskEngine.calculate_asset_risk(
                        active_detections, kb_map, now=now
                    )
                    
                    was_risky = asset.is_risky
                    asset.risk_score = score
                    asset.risk_level = risk_lvl
                    asset.is_risky = is_risky
                    asset.total_vulns = total_v
                    asset.critical_vulns = crit_v
                    asset.high_vulns = high_v
                    assets_updated += 1

                    # Check Alert & Telegram Dispatch
                    if is_risky:
                        # Check last alert cooldown
                        cooldown_cutoff = now - timedelta(hours=settings.TELEGRAM_COOLDOWN_HOURS)
                        recent_alert_res = await db.execute(
                            select(Alert)
                            .where(Alert.asset_id == asset.id, Alert.created_at >= cooldown_cutoff)
                            .order_by(Alert.created_at.desc())
                        )
                        recent_alert = recent_alert_res.scalar_one_or_none()

                        # Alert title and message
                        alert_title = f"{risk_lvl} Risk Flagged: {asset.ip_address or asset.fqdn}"
                        top_dets = sorted(active_detections, key=lambda d: d.severity, reverse=True)
                        alert_msg = f"Asset {asset.ip_address} ({asset.fqdn}) scored {score} with {crit_v} Critical and {high_v} High vulnerabilities."

                        dispatched_telegram = False
                        if settings.TELEGRAM_ENABLED and (recent_alert is None or not was_risky):
                            # Dispatch to Telegram
                            tg_text = TelegramService.format_asset_alert(asset, top_dets, kb_map)
                            tg_result = await TelegramService.send_message(tg_text)
                            dispatched_telegram = tg_result.get("success", False)

                        # Create Alert Record if no alert in cooldown window
                        if recent_alert is None or not was_risky:
                            alert_record = Alert(
                                asset_id=asset.id,
                                alert_type="RISK_FLAGGED",
                                title=alert_title,
                                message=alert_msg,
                                severity=risk_lvl,
                                is_resolved=False,
                                dispatched_to_telegram=dispatched_telegram,
                                telegram_sent_at=now if dispatched_telegram else None,
                                created_at=now,
                            )
                            db.add(alert_record)
                            alerts_triggered += 1

                # Update system setting with last sync timestamp
                last_sync_str = now.isoformat()
                sync_setting = await db.get(SystemSetting, "last_sync_time")
                if sync_setting:
                    sync_setting.value = last_sync_str
                else:
                    db.add(SystemSetting(key="last_sync_time", value=last_sync_str, description="Timestamp of last Qualys sync"))

                await db.commit()

                result_msg = f"Sync completed successfully. Updated {assets_updated} assets, ingested {len(parsed_kb_list)} KB items, triggered {alerts_triggered} alerts."
                current_sync_status["status"] = "Idle"
                current_sync_status["last_run"] = last_sync_str
                current_sync_status["message"] = result_msg

                return {
                    "success": True,
                    "message": result_msg,
                    "assets_updated": assets_updated,
                    "kb_items": len(parsed_kb_list),
                    "alerts_triggered": alerts_triggered,
                    "timestamp": last_sync_str,
                }

            except Exception as e:
                await db.rollback()
                err_msg = f"Sync failed: {str(e)}"
                logger.error(err_msg, exc_info=True)
                current_sync_status["status"] = "Error"
                current_sync_status["message"] = err_msg
                return {"success": False, "message": err_msg}
