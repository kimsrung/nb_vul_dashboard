import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, AsyncSessionLocal
from app.api.deps import require_admin, require_viewer
from app.models.user import User
from app.models.sync_job import SyncJob
from app.schemas.sync import (
    SyncJobResponse,
    SyncTriggerResponse,
    SyncStatusResponse,
)
from app.services.sync_runner import SyncRunner
from app.services.sync_service import SyncService
from app.services.misp_sync_service import MispSyncService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sync", tags=["Background Sync Operations"])


async def _run_bg_qualys_sync(mode: str, username: str, job_id: int):
    async with AsyncSessionLocal() as session:
        await SyncService.run_sync(
            db=session,
            sync_mode=mode,
            manual_trigger=True,
            triggered_by=username,
            job_id=job_id,
        )


async def _run_bg_misp_sync(username: str, job_id: int):
    await MispSyncService.run_sync(
        sync_mode="delta",
        manual_trigger=True,
        triggered_by=username,
        job_id=job_id,
    )


@router.post("/qualys", response_model=SyncTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_qualys_sync(
    background_tasks: BackgroundTasks,
    mode: str = Query("delta", pattern="^(delta|full)$"),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Trigger an asynchronous Qualys asset & vulnerability synchronization job."""
    job, conflict = await SyncRunner.acquire_job(
        session=db,
        source="qualys",
        sync_mode=mode,
        trigger_type="manual",
        triggered_by=admin.username,
    )
    if conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=conflict,
        )

    background_tasks.add_task(_run_bg_qualys_sync, mode, admin.username, job.id)
    return SyncTriggerResponse(
        success=True,
        message=f"Qualys {mode} synchronization started in background.",
        job_id=job.id,
        status="running",
    )


@router.post("/misp", response_model=SyncTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_misp_sync(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Trigger an asynchronous MISP threat intelligence ingestion and inventory evaluation job."""
    job, conflict = await SyncRunner.acquire_job(
        session=db,
        source="misp",
        sync_mode="delta",
        trigger_type="manual",
        triggered_by=admin.username,
    )
    if conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=conflict,
        )

    background_tasks.add_task(_run_bg_misp_sync, admin.username, job.id)
    return SyncTriggerResponse(
        success=True,
        message="MISP threat intelligence synchronization started in background.",
        job_id=job.id,
        status="running",
    )


@router.get("/status", response_model=SyncStatusResponse)
async def get_sync_status(
    source: str = Query("qualys", pattern="^(qualys|misp)$"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve the current active job progress or the most recent completed job metrics."""
    res = await SyncRunner.get_sync_status(session=db, source=source)
    return res


@router.post("/cancel/{job_id}")
async def cancel_sync_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Cancel a running sync job."""
    job = await db.get(SyncJob, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sync job not found")

    if job.status != "running":
        return {"success": False, "message": f"Job #{job_id} is not running (status: {job.status})."}

    from datetime import datetime, timezone
    job.status = "cancelled"
    job.message = f"Cancelled by {admin.username}"
    job.completed_at = datetime.now(timezone.utc)
    job.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"success": True, "message": f"Sync job #{job_id} cancelled."}
