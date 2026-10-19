from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    
    alert_type = Column(String(50), default="RISK_FLAGGED", nullable=False)  # "RISK_FLAGGED" | "SLA_BREACH" | "CRITICAL_RTI"
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default="Critical", nullable=False)  # "Critical" | "High" | "Medium"
    
    is_resolved = Column(Boolean, default=False, nullable=False, index=True)
    dispatched_to_telegram = Column(Boolean, default=False, nullable=False)
    telegram_sent_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    asset = relationship("Asset", back_populates="alerts")
