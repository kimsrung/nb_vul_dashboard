import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.services.sync_service import SyncService
from app.services.misp_sync_service import MispSyncService

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def scheduled_qualys_delta_sync_job():
    logger.info("Executing scheduled Qualys incremental delta sync job...")
    async with AsyncSessionLocal() as session:
        try:
            res = await SyncService.run_sync(session, sync_mode="delta", manual_trigger=False, triggered_by="scheduler")
            logger.info(f"Scheduled Qualys delta sync completed: {res.get('message')}")
        except Exception as e:
            logger.error(f"Error in scheduled Qualys delta sync job: {e}", exc_info=True)


async def scheduled_qualys_full_sync_job():
    logger.info("Executing scheduled weekly Qualys full reconciliation sync job...")
    async with AsyncSessionLocal() as session:
        try:
            res = await SyncService.run_sync(session, sync_mode="full", manual_trigger=False, triggered_by="scheduler")
            logger.info(f"Scheduled weekly Qualys full reconciliation sync completed: {res.get('message')}")
        except Exception as e:
            logger.error(f"Error in scheduled weekly Qualys full sync job: {e}", exc_info=True)


async def scheduled_misp_sync_job():
    logger.info("Executing scheduled MISP FS-ISAC proactive threat sync...")
    if not settings.MISP_ENABLED:
        logger.info("MISP integration is disabled. Skipping scheduled sync.")
        return

    try:
        res = await MispSyncService.run_sync(sync_mode="delta", manual_trigger=False, triggered_by="scheduler")
        logger.info(f"Scheduled MISP FS-ISAC sync completed: {res.get('message')}")
    except Exception as e:
        logger.error(f"Error in scheduled MISP sync job: {e}", exc_info=True)


def start_scheduler():
    interval_hours = max(1, settings.QUALYS_SYNC_INTERVAL_HOURS)
    scheduler.add_job(
        scheduled_qualys_delta_sync_job,
        "interval",
        hours=interval_hours,
        id="qualys_sync_job",
        replace_existing=True,
    )

    # Weekly full reconciliation sync on Sunday at 02:00 UTC
    scheduler.add_job(
        scheduled_qualys_full_sync_job,
        "cron",
        day_of_week="sun",
        hour=2,
        minute=0,
        id="qualys_full_sync_job",
        replace_existing=True,
    )

    misp_desc = "MISP FS-ISAC scheduled sync: DISABLED (100% ZeroMQ stream + manual UI triggers)"
    if settings.MISP_SYNC_INTERVAL_HOURS > 0:
        scheduler.add_job(
            scheduled_misp_sync_job,
            "interval",
            hours=settings.MISP_SYNC_INTERVAL_HOURS,
            id="misp_sync_job",
            replace_existing=True,
        )
        misp_desc = f"MISP FS-ISAC: every {settings.MISP_SYNC_INTERVAL_HOURS}h"

    scheduler.start()
    logger.info(
        f"Background sync scheduler started (Qualys delta: every {interval_hours}h, Qualys full: weekly Sun 02:00 UTC, {misp_desc})"
    )


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Background sync scheduler stopped.")
