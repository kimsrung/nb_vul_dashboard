from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, JSON, DateTime
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(50), nullable=False, index=True)  # e.g., "DELETE_ASSET", "RESOLVE_ALERT", "UPDATE_REMEDIATION", "ASSIGN_OWNER"
    target_type = Column(String(50), nullable=False, index=True)  # e.g., "Asset", "Alert", "Detection", "SystemSetting"
    target_id = Column(String(100), nullable=False, index=True)
    target_name = Column(String(255), nullable=True)  # Human-readable identifier e.g. "bk-appcore-sit (10.20.6.190)"
    
    actor_id = Column(Integer, nullable=True, index=True)
    actor_username = Column(String(100), nullable=False, index=True)
    actor_role = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(50), nullable=True)
    
    details = Column(JSON, default=dict, nullable=False)  # Snapshot / metadata
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
