from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    qualys_id = Column(String(100), unique=True, index=True, nullable=False)
    server_name = Column(String(255), index=True, nullable=True)  # Clean server / host name e.g. bk-appcore-sit
    ip_address = Column(String(50), index=True, nullable=True)
    ipv6_address = Column(String(100), nullable=True)
    fqdn = Column(String(255), index=True, nullable=True)
    netbios_name = Column(String(100), nullable=True)
    os_name = Column(String(255), nullable=True)
    os_family = Column(String(100), index=True, nullable=True)  # e.g., "Linux", "Windows", "Network"
    tags = Column(JSON, default=list, nullable=False)  # Filtered tag strings
    
    # Ownership & Point of Contact (PoC)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    owner_username = Column(String(100), nullable=True)
    poc_name = Column(String(150), nullable=True, index=True)  # Individual person name e.g. "Sok Dara"
    poc_email = Column(String(255), nullable=True, index=True)  # Individual email e.g. "sok.dara@nbc.gov.kh"

    last_scan_date = Column(DateTime(timezone=True), nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False, index=True)
    risk_level = Column(String(20), default="Low", nullable=False, index=True)  # "Critical", "High", "Medium", "Low"
    is_risky = Column(Boolean, default=False, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)  # False if decommissioned / not reporting in Qualys
    
    total_vulns = Column(Integer, default=0, nullable=False)
    critical_vulns = Column(Integer, default=0, nullable=False)
    high_vulns = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    owner = relationship("User", back_populates="assets", foreign_keys=[owner_id])
    detections = relationship("Detection", back_populates="asset", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="asset", cascade="all, delete-orphan")
    software_items = relationship("AssetSoftware", back_populates="asset", cascade="all, delete-orphan")
