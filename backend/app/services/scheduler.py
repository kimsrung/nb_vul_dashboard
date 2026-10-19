import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.services.sync_service import SyncService

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def scheduled_sync_job():
    logger.info("Executing scheduled Qualys sync job...")
    async with AsyncSessionLocal() as session:
        try:
            res = await SyncService.run_sync(session, manual_trigger=False)
            logger.info(f"Scheduled sync completed: {res.get('message')}")
        except Exception as e:
            logger.error(f"Error in scheduled sync job: {e}", exc_info=True)


def start_scheduler():
    interval_hours = max(1, settings.QUALYS_SYNC_INTERVAL_HOURS)
    scheduler.add_job(
        scheduled_sync_job,
        "interval",
        hours=interval_hours,
        id="qualys_sync_job",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(f"Qualys background sync scheduler started (interval: every {interval_hours} hours)")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Qualys background sync scheduler stopped.")
