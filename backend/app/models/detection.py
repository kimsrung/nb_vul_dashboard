from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from app.core.database import Base


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    qid = Column(Integer, ForeignKey("knowledge_base.qid"), nullable=False, index=True)
    
    detection_type = Column(String(50), default="Confirmed", nullable=False)  # "Confirmed" | "Potential" | "Information"
    severity = Column(Integer, default=1, nullable=False, index=True)
    status = Column(String(50), default="Active", nullable=False, index=True)  # "Active" | "New" | "Re-Opened" | "Fixed"
    
    first_found_date = Column(DateTime, nullable=True)
    last_found_date = Column(DateTime, nullable=True)
    times_found = Column(Integer, default=1, nullable=False)
    
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    scanner_results = Column(Text, nullable=True)  # Qualys scanner proof output
    
    # Remediation workflow
    remediation_status = Column(String(50), default="Open", nullable=False, index=True)  # "Open" | "In_Progress" | "Acknowledged" | "False_Positive" | "Resolved"
    remediation_notes = Column(Text, nullable=True)
    updated_by = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    asset = relationship("Asset", back_populates="detections")
    knowledge_base = relationship("KnowledgeBase", back_populates="detections")
