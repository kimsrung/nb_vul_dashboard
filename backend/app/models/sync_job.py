from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, JSON, DateTime, Text
from app.core.database import Base


class SyncJob(Base):
    __tablename__ = "sync_jobs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(32), nullable=False, index=True)  # "qualys" or "misp"
    sync_mode = Column(String(32), nullable=False, default="delta")  # "delta" or "full"
    trigger_type = Column(String(32), nullable=False, default="manual")  # "manual" or "scheduled"
    status = Column(String(32), nullable=False, default="pending", index=True)  # "pending", "running", "completed", "failed", "cancelled"

    progress_pct = Column(Integer, nullable=False, default=0)  # 0 to 100
    total_items = Column(Integer, nullable=False, default=0)
    processed_items = Column(Integer, nullable=False, default=0)
    message = Column(String(500), nullable=False, default="Starting sync...")
    details = Column(JSON, nullable=False, default=dict)  # Metrics, breakdowns, counts
    error_message = Column(Text, nullable=True)
    triggered_by = Column(String(100), nullable=True)  # Username or "scheduler"

    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)  # Heartbeat
