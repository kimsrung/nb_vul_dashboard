import logging
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.setting import SystemSetting
from app.services.sync_service import SyncService
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def scheduled_sync_job():
    logger.info("Executing scheduled Qualys sync job...")
    async with AsyncSessionLocal() as session:
        try:
            res = await SyncService.run_sync(session, manual_trigger=False)
            logger.info(f"Scheduled Qualys sync completed: {res.get('message')}")
        except Exception as e:
            logger.error(f"Error in scheduled Qualys sync job: {e}", exc_info=True)


async def scheduled_misp_sync_job():
    logger.info("Executing scheduled MISP FS-ISAC proactive threat sync...")
    if not settings.MISP_ENABLED:
        logger.info("MISP integration is disabled. Skipping scheduled sync.")
        return

    async with AsyncSessionLocal() as session:
        try:
            from sqlalchemy import select
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
                elif k == "misp_mock_mode":
                    settings.MISP_MOCK_MODE = v.lower() in ("true", "1")

            client = MispClient(
                base_url=settings.MISP_URL,
                api_key=settings.MISP_API_KEY,
                creator_org=settings.MISP_CREATOR_ORG,
                tag_filter=settings.MISP_TAG_FILTER,
                mock_mode=settings.MISP_MOCK_MODE,
            )
            advisories = await client.fetch_fs_isac_events()
            if not advisories:
                logger.info("No FS-ISAC advisories fetched from MISP.")
                return

            proactive_matches = 0
            for adv in advisories:
                record = await ProactiveAssessmentEngine.assess_cve(session, adv)
                if record.match_type == "INVENTORY_PROACTIVE" and record.affected_assets_count > 0:
                    proactive_matches += 1
                    if (
                        settings.TELEGRAM_ENABLED
                        and (record.severity or "").upper() in ("CRITICAL", "HIGH")
                        and not record.dispatched_telegram
                    ):
                        try:
                            tg_text = TelegramService.format_misp_assessment_alert(record)
                            await TelegramService.send_message(tg_text)
                            record.dispatched_telegram = True
                        except Exception as te:
                            logger.error(f"Telegram dispatch failed: {te}")

            now_str = datetime.now(timezone.utc).isoformat()
            sync_setting = await session.get(SystemSetting, "misp_last_sync_time")
            if sync_setting:
                sync_setting.value = now_str
            else:
                session.add(SystemSetting(key="misp_last_sync_time", value=now_str, description="Timestamp of last MISP FS-ISAC sync"))
            await session.commit()
            logger.info(f"Scheduled MISP FS-ISAC sync completed: {len(advisories)} advisories evaluated, {proactive_matches} active proactive alert(s).")
        except Exception as e:
            logger.error(f"Error in scheduled MISP sync job: {e}", exc_info=True)


def start_scheduler():
    interval_hours = max(1, settings.QUALYS_SYNC_INTERVAL_HOURS)
    scheduler.add_job(
        scheduled_sync_job,
        "interval",
        hours=interval_hours,
        id="qualys_sync_job",
        replace_existing=True,
    )

    misp_interval = max(1, settings.MISP_SYNC_INTERVAL_HOURS)
    scheduler.add_job(
        scheduled_misp_sync_job,
        "interval",
        hours=misp_interval,
        id="misp_sync_job",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        f"Background sync scheduler started (Qualys: every {interval_hours}h, MISP FS-ISAC: every {misp_interval}h)"
    )


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Background sync scheduler stopped.")
