import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.sync_job import SyncJob
from app.services.sync_runner import SyncRunner, STALE_HEARTBEAT_MINUTES
from app.services.scheduler import (
    scheduled_qualys_delta_sync_job,
    scheduled_qualys_full_sync_job,
    scheduled_misp_sync_job,
)


class TestBackgroundSyncRunner:
    @pytest.mark.asyncio
    async def test_trigger_qualys_sync_202_and_status(self, client: AsyncClient, admin_headers: dict):
        res = await client.post("/api/v1/sync/qualys?mode=delta", headers=admin_headers)
        assert res.status_code == 202
        data = res.json()
        assert data.get("success") is True
        assert data.get("status") == "running"
        assert "job_id" in data
        job_id = data["job_id"]
        assert isinstance(job_id, int)

        # Check status
        status_res = await client.get("/api/v1/sync/status?source=qualys", headers=admin_headers)
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert "is_running" in status_data
        assert "latest_completed_job" in status_data

    @pytest.mark.asyncio
    async def test_trigger_qualys_full_sync_mode(self, client: AsyncClient, admin_headers: dict):
        res = await client.post("/api/v1/sync/qualys?mode=full", headers=admin_headers)
        assert res.status_code == 202
        data = res.json()
        assert data.get("success") is True
        assert data.get("status") == "running"
        assert "job_id" in data

        # Check status reflects qualys source
        status_res = await client.get("/api/v1/sync/status?source=qualys", headers=admin_headers)
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert "is_running" in status_data

    @pytest.mark.asyncio
    async def test_trigger_misp_sync_202_and_status(self, client: AsyncClient, admin_headers: dict):
        res = await client.post("/api/v1/sync/misp", headers=admin_headers)
        assert res.status_code == 202
        data = res.json()
        assert data.get("success") is True
        assert data.get("status") == "running"
        assert "job_id" in data

        # Check status
        status_res = await client.get("/api/v1/sync/status?source=misp", headers=admin_headers)
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert "is_running" in status_data

    @pytest.mark.asyncio
    async def test_sync_rbac_viewer_and_analyst_forbidden(
        self, client: AsyncClient, viewer_headers: dict, analyst_headers: dict
    ):
        # Viewer rejected
        v_res = await client.post("/api/v1/sync/qualys", headers=viewer_headers)
        assert v_res.status_code == 403

        v_misp = await client.post("/api/v1/sync/misp", headers=viewer_headers)
        assert v_misp.status_code == 403

        # Analyst rejected (Admin only)
        a_res = await client.post("/api/v1/sync/qualys", headers=analyst_headers)
        assert a_res.status_code == 403

        a_misp = await client.post("/api/v1/sync/misp", headers=analyst_headers)
        assert a_misp.status_code == 403

        # Viewer can read sync status
        read_res = await client.get("/api/v1/sync/status?source=qualys", headers=viewer_headers)
        assert read_res.status_code == 200

    @pytest.mark.asyncio
    async def test_sync_concurrency_lock_returns_409(self, client: AsyncClient, admin_headers: dict):
        """Simulate an active running job and assert concurrent triggers are rejected with 409 Conflict."""
        async with AsyncSessionLocal() as session:
            # Clean any old running jobs
            running_jobs = await session.execute(select(SyncJob).where(SyncJob.status == "running"))
            for j in running_jobs.scalars().all():
                j.status = "completed"
            await session.commit()

            # Create an artificial active running job
            now = datetime.now(timezone.utc)
            mock_active = SyncJob(
                source="qualys",
                sync_mode="delta",
                trigger_type="manual",
                status="running",
                progress_pct=42,
                total_items=100,
                processed_items=42,
                message="Testing lock...",
                details={},
                triggered_by="admin",
                started_at=now,
                updated_at=now,
            )
            session.add(mock_active)
            await session.commit()
            await session.refresh(mock_active)
            active_id = mock_active.id

        # Attempt to trigger concurrent Qualys sync
        conflict_res = await client.post("/api/v1/sync/qualys?mode=delta", headers=admin_headers)
        assert conflict_res.status_code == 409
        conflict_data = conflict_res.json()
        assert "already in progress" in conflict_data.get("detail", "")
        assert "42%" in conflict_data.get("detail", "")

        # Clean up mock job so subsequent tests can run
        async with AsyncSessionLocal() as session:
            j = await session.get(SyncJob, active_id)
            if j:
                j.status = "completed"
                await session.commit()

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_job_returns_404(self, client: AsyncClient, admin_headers: dict):
        res = await client.post("/api/v1/sync/cancel/999999", headers=admin_headers)
        assert res.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_active_job_and_lifecycle(self, client: AsyncClient, admin_headers: dict):
        """Verify cancelling an active running job and rejecting cancellation of non-running jobs."""
        async with AsyncSessionLocal() as session:
            now = datetime.now(timezone.utc)
            job = SyncJob(
                source="qualys",
                sync_mode="full",
                trigger_type="manual",
                status="running",
                progress_pct=15,
                total_items=200,
                processed_items=30,
                message="Long running reconciliation...",
                details={},
                triggered_by="admin",
                started_at=now,
                updated_at=now,
            )
            session.add(job)
            await session.commit()
            await session.refresh(job)
            test_job_id = job.id

        # Cancel the active job
        cancel_res = await client.post(f"/api/v1/sync/cancel/{test_job_id}", headers=admin_headers)
        assert cancel_res.status_code == 200
        cancel_data = cancel_res.json()
        assert cancel_data["success"] is True
        assert "cancelled" in cancel_data["message"].lower()

        # Verify job status in database is now 'cancelled'
        async with AsyncSessionLocal() as session:
            cancelled_job = await session.get(SyncJob, test_job_id)
            assert cancelled_job is not None
            assert cancelled_job.status == "cancelled"
            assert "admin" in cancelled_job.message

        # Attempting to cancel again should gracefully return success=False
        retry_cancel = await client.post(f"/api/v1/sync/cancel/{test_job_id}", headers=admin_headers)
        assert retry_cancel.status_code == 200
        retry_data = retry_cancel.json()
        assert retry_data["success"] is False
        assert "not running" in retry_data["message"]

    @pytest.mark.asyncio
    async def test_stale_job_auto_recovery_mechanism(self):
        """Verify that jobs without recent worker heartbeats (>15 min) are automatically recovered."""
        async with AsyncSessionLocal() as session:
            # Create an abandoned job from 25 minutes ago
            stale_time = datetime.now(timezone.utc) - timedelta(minutes=STALE_HEARTBEAT_MINUTES + 10)
            stale_job = SyncJob(
                source="qualys",
                sync_mode="delta",
                trigger_type="manual",
                status="running",
                progress_pct=50,
                total_items=100,
                processed_items=50,
                message="Crashed worker simulation",
                details={},
                triggered_by="admin",
                started_at=stale_time,
                updated_at=stale_time,
            )
            session.add(stale_job)
            await session.commit()
            await session.refresh(stale_job)
            stale_id = stale_job.id

            # Invoke stale cleanup
            await SyncRunner.cleanup_stale_jobs(session, source="qualys")

            # Check that job was marked failed and lock freed
            updated_job = await session.get(SyncJob, stale_id)
            assert updated_job.status == "failed"
            assert "timed out" in updated_job.error_message.lower()

            # Verify we can now acquire a new job without conflict
            new_job, conflict = await SyncRunner.acquire_job(
                session=session,
                source="qualys",
                sync_mode="delta",
                trigger_type="manual",
                triggered_by="admin",
            )
            assert conflict is None
            assert new_job is not None
            assert new_job.status == "running"

            # Clean up new job
            new_job.status = "completed"
            await session.commit()

    @pytest.mark.asyncio
    async def test_scheduler_direct_job_executions(self):
        """Directly invoke background scheduler sync tasks to verify graceful execution."""
        # Scheduled Qualys delta sync
        await scheduled_qualys_delta_sync_job()

        # Scheduled Qualys full sync
        await scheduled_qualys_full_sync_job()

        # Scheduled MISP sync
        await scheduled_misp_sync_job()
