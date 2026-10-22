from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class AssetSoftware(Base):
    __tablename__ = "asset_software"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    
    product_name = Column(String(100), nullable=False, index=True)  # e.g., "openssh", "nginx", "openssl", "log4j"
    vendor = Column(String(100), nullable=True)  # e.g., "OpenBSD", "F5", "Apache", "Canonical"
    version = Column(String(50), nullable=False, index=True)  # e.g., "8.9p1", "1.24.0", "3.0.2", "2.14.1"
    package_name = Column(String(150), nullable=True)  # e.g., "openssh-server", "nginx-core", "libssl3"
    install_path = Column(String(255), nullable=True)  # e.g., "/usr/sbin/sshd", "/opt/analytics/lib/"
    port = Column(Integer, nullable=True)  # e.g., 22, 80, 443, 8080
    cpe = Column(String(255), nullable=True)  # e.g., "cpe:/a:openbsd:openssh:8.9p1"

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    asset = relationship("Asset", back_populates="software_items")
