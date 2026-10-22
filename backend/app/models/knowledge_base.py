from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Float, JSON, DateTime
from sqlalchemy.orm import relationship
from app.core.database import Base


class KnowledgeBase(Base):
    __tablename__ = "knowledge_base"

    qid = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False, index=True)
    category = Column(String(100), nullable=True)
    vuln_type = Column(String(50), nullable=True)  # "Vulnerability" | "Practice" | "Information"
    severity = Column(Integer, nullable=False, default=1)  # 1 to 5
    cvss_v2 = Column(Float, nullable=True)
    cvss_v3 = Column(Float, nullable=True)
    
    diagnosis = Column(Text, nullable=True)
    consequence = Column(Text, nullable=True)
    solution = Column(Text, nullable=True)
    patches = Column(JSON, nullable=True)  # List of {url, description}
    workaround = Column(Text, nullable=True)
    cve_list = Column(JSON, nullable=True)  # List of CVE strings e.g. ["CVE-2023-1234"]
    threat_intel_flags = Column(JSON, nullable=True)  # RTI flags: {"exploit_public": bool, "ransomware": bool, etc.}
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    detections = relationship("Detection", back_populates="knowledge_base")
