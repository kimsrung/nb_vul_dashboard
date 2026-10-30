from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class SyncJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    sync_mode: str
    trigger_type: str
    status: str
    progress_pct: int
    total_items: int
    processed_items: int
    message: str
    details: Dict[str, Any] = {}
    error_message: Optional[str] = None
    triggered_by: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    updated_at: datetime


class SyncTriggerResponse(BaseModel):
    success: bool
    message: str
    job_id: Optional[int] = None
    status: str = "running"


class SyncStatusResponse(BaseModel):
    is_running: bool
    active_job: Optional[SyncJobResponse] = None
    latest_completed_job: Optional[SyncJobResponse] = None
