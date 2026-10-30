import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.setting import SystemSetting
from app.models.misp_feed import MispCveAssessment
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService
from app.services.sync_runner import SyncRunner
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class MispSyncService:
    """Orchestrates asynchronous MISP threat intelligence synchronization with persistent job tracking."""

    @classmethod
    async def run_sync(
        cls,
        sync_mode: str = "delta",
        manual_trigger: bool = False,
        triggered_by: Optional[str] = None,
        job_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute MISP threat intelligence ingestion.
        Supports:
          - 'delta': Queries recent advisories since last sync watermark.
          - 'full': Re-evaluates full FS-ISAC CVE feed.
        """
        async with AsyncSessionLocal() as session:
            # 1. Acquire job if not pre-allocated
            if job_id is None:
                job, err = await SyncRunner.acquire_job(
                    session=session,
                    source="misp",
                    sync_mode=sync_mode,
                    trigger_type="manual" if manual_trigger else "scheduled",
                    triggered_by=triggered_by,
                )
                if err:
                    return {"success": False, "message": err}
                job_id = job.id

            try:
                await SyncRunner.update_progress(
                    job_id=job_id,
                    processed_items=0,
                    total_items=100,
                    message="Initializing MISP client and querying threat advisories...",
                )

                # 2. Load latest settings
                settings_res = await session.execute(select(SystemSetting))
                for row in settings_res.scalars().all():
                    k, v = row.key, row.value
                    if k == "misp_url" and v:
                        settings.MISP_URL = v
                    elif k == "misp_api_key" and v:
                        settings.MISP_API_KEY = v
                    elif k == "misp_creator_org" and v:
                        settings.MISP_CREATOR_ORG = v
                    elif k == "misp_tag_filter" and v:
                        settings.MISP_TAG_FILTER = v
                    elif k == "misp_feed_tag" and v:
                        settings.MISP_FEED_TAG = v
                    elif k == "misp_mock_mode":
                        settings.MISP_MOCK_MODE = v.lower() in ("true", "1")
                    elif k == "misp_verify_ssl":
                        settings.MISP_VERIFY_SSL = v.lower() in ("true", "1")

                client = MispClient(
                    base_url=settings.MISP_URL,
                    api_key=settings.MISP_API_KEY,
                    creator_org=settings.MISP_CREATOR_ORG,
                    tag_filter=settings.MISP_TAG_FILTER,
                    feed_tag=settings.MISP_FEED_TAG,
                    mock_mode=settings.MISP_MOCK_MODE,
                    verify_ssl=settings.MISP_VERIFY_SSL,
                )

                # 3. Determine delta watermark if in delta mode
                watermark: Optional[str] = None
                if sync_mode == "delta":
                    watermark_setting = await session.get(SystemSetting, "misp_last_sync_time")
                    if watermark_setting and watermark_setting.value:
                        watermark = watermark_setting.value

                advisories = await client.fetch_fs_isac_events()
                total_adv = len(advisories)

                if total_adv == 0:
                    result_msg = "No new FS-ISAC advisories fetched from MISP."
                    await SyncRunner.complete_job(
                        job_id=job_id,
                        message=result_msg,
                        details={"assessments_run": 0, "pre_scan_matches": 0, "qualys_confirmed": 0, "clean_cves": 0},
                    )
                    return {
                        "success": True,
                        "message": result_msg,
                        "assessments_run": 0,
                        "pre_scan_matches": 0,
                        "qualys_confirmed": 0,
                        "clean_cves": 0,
                    }

                await SyncRunner.update_progress(
                    job_id=job_id,
                    processed_items=0,
                    total_items=total_adv,
                    message=f"Fetched {total_adv} advisories. Starting inventory assessment...",
                )

                assessments_run = 0
                pre_scan_matches = 0
                qualys_confirmed = 0
                clean_cves = 0
                alerts_to_dispatch: List[int] = []

                # 4. Ingest and assess each advisory
                for idx, adv in enumerate(advisories, 1):
                    record = await ProactiveAssessmentEngine.assess_cve(session, adv)
                    assessments_run += 1
                    if record.match_type == "INVENTORY_PROACTIVE":
                        pre_scan_matches += 1
                    elif record.match_type == "QUALYS_CONFIRMED":
                        qualys_confirmed += 1
                    else:
                        clean_cves += 1

                    # Queue telegram alerts for affected servers on Critical or High advisories
                    if (
                        settings.TELEGRAM_ENABLED
                        and record.affected_assets_count > 0
                        and (record.severity or "").upper() in ("CRITICAL", "HIGH")
                        and not record.dispatched_telegram
                    ):
                        alerts_to_dispatch.append(record.id)

                    # Update progress every 25 items or at completion
                    if idx % 25 == 0 or idx == total_adv:
                        await SyncRunner.update_progress(
                            job_id=job_id,
                            processed_items=idx,
                            total_items=total_adv,
                            message=f"Assessed {idx}/{total_adv} advisories ({adv.get('cve_id')})...",
                            details={
                                "pre_scan_matches": pre_scan_matches,
                                "qualys_confirmed": qualys_confirmed,
                                "clean_cves": clean_cves,
                            },
                        )

                # 5. Dispatch any Telegram notifications in background
                if alerts_to_dispatch:
                    for aid in alerts_to_dispatch:
                        try:
                            rec = await session.get(MispCveAssessment, aid)
                            if rec and not rec.dispatched_telegram:
                                tg_text = TelegramService.format_misp_assessment_alert(rec)
                                tg_res = await TelegramService.send_message(tg_text)
                                if tg_res.get("success"):
                                    rec.dispatched_telegram = True
                                    rec.telegram_sent_at = datetime.now(timezone.utc)
                                    await session.commit()
                        except Exception as te:
                            logger.error(f"Failed to dispatch Telegram alert for assessment {aid}: {te}")

                # 6. Update MISP sync settings and watermarks
                now_str = datetime.now(timezone.utc).isoformat()
                sync_setting = await session.get(SystemSetting, "misp_last_sync_time")
                if sync_setting:
                    sync_setting.value = now_str
                else:
                    session.add(SystemSetting(key="misp_last_sync_time", value=now_str, description="Timestamp of last MISP FS-ISAC sync"))

                raw_events_count = getattr(client, "last_events_count", total_adv)
                if raw_events_count:
                    events_setting = await session.get(SystemSetting, "misp_total_events_count")
                    if events_setting:
                        events_setting.value = str(raw_events_count)
                    else:
                        session.add(SystemSetting(key="misp_total_events_count", value=str(raw_events_count), description="Total raw MISP events fetched"))

                await session.commit()

                # 7. Audit log entry
                await AuditService.log_event(
                    db=session,
                    action=f"MISP_{sync_mode.upper()}_SYNC",
                    target_type="SYNC",
                    target_id="misp",
                    target_name=f"MISP Threat Intelligence {sync_mode.capitalize()} Sync",
                    details={
                        "sync_mode": sync_mode,
                        "raw_events_count": raw_events_count,
                        "unique_cves_evaluated": assessments_run,
                        "assessments_run": assessments_run,
                        "pre_scan_matches": pre_scan_matches,
                        "qualys_confirmed": qualys_confirmed,
                        "clean_cves": clean_cves,
                        "manual_trigger": manual_trigger,
                        "triggered_by": triggered_by,
                    },
                )

                summary_msg = (
                    f"Synced {raw_events_count} FS-ISAC events ({assessments_run} unique CVE advisories evaluated): "
                    f"{pre_scan_matches} proactive pre-scan matches, "
                    f"{qualys_confirmed} Qualys confirmed, {clean_cves} clean."
                )

                await SyncRunner.complete_job(
                    job_id=job_id,
                    message=summary_msg,
                    details={
                        "raw_events_count": raw_events_count,
                        "unique_cves_evaluated": assessments_run,
                        "assessments_run": assessments_run,
                        "pre_scan_matches": pre_scan_matches,
                        "qualys_confirmed": qualys_confirmed,
                        "clean_cves": clean_cves,
                    },
                )

                return {
                    "success": True,
                    "message": summary_msg,
                    "raw_events_count": raw_events_count,
                    "assessments_run": assessments_run,
                    "pre_scan_matches": pre_scan_matches,
                    "qualys_confirmed": qualys_confirmed,
                    "clean_cves": clean_cves,
                }

            except Exception as e:
                logger.error(f"MISP sync job #{job_id} failed: {e}", exc_info=True)
                await SyncRunner.fail_job(job_id=job_id, error_message=str(e))
                return {"success": False, "message": f"MISP sync failed: {str(e)}"}
