import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.sync_job import SyncJob

logger = logging.getLogger(__name__)

STALE_HEARTBEAT_MINUTES = 15


class SyncRunner:
    """Manages background synchronization jobs, progress heartbeats, and concurrency locks."""

    @classmethod
    async def cleanup_stale_jobs(cls, session: AsyncSession, source: Optional[str] = None):
        """Mark any jobs lingering in 'running' status without recent heartbeat as failed."""
        threshold = datetime.now(timezone.utc) - timedelta(minutes=STALE_HEARTBEAT_MINUTES)
        stmt = select(SyncJob).where(
            SyncJob.status == "running",
            SyncJob.updated_at < threshold,
        )
        if source:
            stmt = stmt.where(SyncJob.source == source)

        res = await session.execute(stmt)
        stale_jobs = res.scalars().all()
        if stale_jobs:
            now = datetime.now(timezone.utc)
            for job in stale_jobs:
                job.status = "failed"
                job.error_message = f"Job timed out: no worker heartbeat for > {STALE_HEARTBEAT_MINUTES} minutes."
                job.completed_at = now
                job.updated_at = now
                logger.warning(f"Cleared stale sync job #{job.id} ({job.source}) due to inactivity.")
            await session.commit()

    @classmethod
    async def acquire_job(
        cls,
        session: AsyncSession,
        source: str,
        sync_mode: str = "delta",
        trigger_type: str = "manual",
        triggered_by: Optional[str] = None,
    ) -> Tuple[Optional[SyncJob], Optional[str]]:
        """
        Attempt to atomically acquire a sync execution lock for 'source'.
        Returns (SyncJob, None) if acquired, or (None, conflict_message) if another job is running.
        """
        # 1. Clean up stale jobs first
        await cls.cleanup_stale_jobs(session, source=source)

        # 2. Check if a valid running job already exists
        active_stmt = select(SyncJob).where(
            SyncJob.source == source,
            SyncJob.status == "running",
        )
        active_res = await session.execute(active_stmt)
        existing_job = active_res.scalars().first()

        if existing_job:
            pct = existing_job.progress_pct
            msg = f"A {source.upper()} sync is already in progress ({pct}% complete, Job #{existing_job.id})."
            logger.info(f"Cannot acquire sync lock: {msg}")
            return None, msg

        # 3. Create and acquire new job record
        now = datetime.now(timezone.utc)
        job = SyncJob(
            source=source,
            sync_mode=sync_mode,
            trigger_type=trigger_type,
            status="running",
            progress_pct=0,
            total_items=0,
            processed_items=0,
            message=f"Starting {source.upper()} {sync_mode} sync...",
            details={},
            triggered_by=triggered_by or ("scheduler" if trigger_type == "scheduled" else "system"),
            started_at=now,
            updated_at=now,
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)
        logger.info(f"Acquired sync lock for {source.upper()} (Job #{job.id}, mode={sync_mode})")
        return job, None

    @classmethod
    async def update_progress(
        cls,
        job_id: int,
        processed_items: int,
        total_items: int,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Update job progress percentage, processed count, and heartbeat timestamp."""
        async with AsyncSessionLocal() as session:
            job = await session.get(SyncJob, job_id)
            if not job or job.status != "running":
                return

            now = datetime.now(timezone.utc)
            job.processed_items = processed_items
            job.total_items = max(total_items, processed_items)
            job.progress_pct = min(100, int((job.processed_items / max(1, job.total_items)) * 100))
            if message:
                job.message = message
            if details:
                merged = dict(job.details or {})
                merged.update(details)
                job.details = merged
            job.updated_at = now
            await session.commit()

    @classmethod
    async def complete_job(
        cls,
        job_id: int,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Mark job as successfully completed."""
        async with AsyncSessionLocal() as session:
            job = await session.get(SyncJob, job_id)
            if not job:
                return

            now = datetime.now(timezone.utc)
            job.status = "completed"
            job.progress_pct = 100
            job.message = message
            job.completed_at = now
            job.updated_at = now
            if details:
                merged = dict(job.details or {})
                merged.update(details)
                job.details = merged
            await session.commit()
            logger.info(f"Sync Job #{job.id} ({job.source}) completed successfully: {message}")

    @classmethod
    async def fail_job(
        cls,
        job_id: int,
        error_message: str,
    ):
        """Mark job as failed with error details."""
        async with AsyncSessionLocal() as session:
            job = await session.get(SyncJob, job_id)
            if not job:
                return

            now = datetime.now(timezone.utc)
            job.status = "failed"
            job.error_message = error_message
            job.message = f"Sync failed: {error_message[:200]}"
            job.completed_at = now
            job.updated_at = now
            await session.commit()
            logger.error(f"Sync Job #{job.id} ({job.source}) failed: {error_message}")

    @classmethod
    async def get_sync_status(cls, session: AsyncSession, source: str) -> Dict[str, Any]:
        """Query active job status or latest completed job for frontend polling."""
        await cls.cleanup_stale_jobs(session, source=source)

        # 1. Check for currently running job
        active_stmt = (
            select(SyncJob)
            .where(SyncJob.source == source, SyncJob.status == "running")
            .order_by(desc(SyncJob.id))
            .limit(1)
        )
        active_res = await session.execute(active_stmt)
        active_job = active_res.scalars().first()

        # 2. Check for latest completed or failed job
        latest_stmt = (
            select(SyncJob)
            .where(SyncJob.source == source, SyncJob.status != "running")
            .order_by(desc(SyncJob.id))
            .limit(1)
        )
        latest_res = await session.execute(latest_stmt)
        latest_job = latest_res.scalars().first()

        return {
            "is_running": active_job is not None,
            "active_job": active_job,
            "latest_completed_job": latest_job,
        }
