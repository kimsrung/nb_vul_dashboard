from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, JSON, DateTime
from app.core.database import Base


class MispCveAssessment(Base):
    __tablename__ = "misp_cve_assessments"

    id = Column(Integer, primary_key=True, index=True)
    misp_event_id = Column(String(50), nullable=True, index=True)  # Original MISP event ID (e.g., "8932")
    misp_event_date = Column(DateTime(timezone=True), nullable=True, index=True)  # Published date from MISP
    cve_id = Column(String(50), index=True, nullable=False)  # e.g., "CVE-2024-6387"
    source = Column(String(50), default="FS-ISAC", nullable=False, index=True)  # Strictly "FS-ISAC"
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="High", nullable=False)  # "Critical", "High", "Medium", "Low"
    cvss_score = Column(Float, nullable=True)
    
    affected_product = Column(String(100), nullable=False)  # e.g., "OpenSSH", "NGINX", "XZ Utils"
    vulnerable_versions = Column(String(150), nullable=False)  # e.g., "< 9.8p1"
    fixed_versions = Column(String(150), nullable=True)  # e.g., ">= 9.8p1"

    # Match Type:
    # "QUALYS_CONFIRMED" -> Already detected by Qualys scanner on assets
    # "INVENTORY_PROACTIVE" -> Pre-scan proactive match based on installed software inventory
    # "NO_ASSETS_AFFECTED" -> Evaluated against inventory, no servers running vulnerable versions
    match_type = Column(String(50), nullable=False, index=True)
    
    # Confidence Level: "High" | "Medium" | "Low" | "None"
    confidence = Column(String(100), default="High", nullable=False)
    
    affected_assets_count = Column(Integer, default=0, nullable=False)
    
    # Detailed Assessment Report (JSON):
    # {
    #   "summary": "...",
    #   "affected_assets": [
    #     {
    #       "asset_id": 6,
    #       "server_name": "Bakong SIT",
    #       "ip_address": "10.20.6.190",
    #       "os_name": "Ubuntu 22.04 LTS",
    #       "evidence": "Installed package openssh-server 8.9p1 (Path: /usr/sbin/sshd)",
    #       "installed_version": "8.9p1",
    #       "confidence": "High",
    #       "recommended_verification": "ssh -V && dpkg -l | grep openssh-server"
    #     }
    #   ],
    #   "recommended_actions": "Upgrade OpenSSH to 9.8p1 or apply vendor patch.",
    #   "verification_command": "dpkg -l | grep openssh-server",
    #   "matched_qid": 150682 // if Qualys confirmed
    # }
    assessment_report = Column(JSON, default=dict, nullable=False)

    dispatched_telegram = Column(Boolean, default=False, nullable=False)
    telegram_sent_at = Column(DateTime(timezone=True), nullable=True)

    status = Column(String(30), default="Pending", nullable=False)  # "Pending", "Acknowledged", "Remediated", "False_Positive"

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
