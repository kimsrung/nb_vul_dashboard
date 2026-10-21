from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class AffectedServerItem(BaseModel):
    asset_id: int
    server_name: Optional[str] = None
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    evidence: str
    installed_version: Optional[str] = None
    confidence: str
    recommended_verification: Optional[str] = None


class AlertItem(BaseModel):
    id: int
    cve_id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    cvss_score: Optional[float] = None
    affected_product: str
    vulnerable_versions: str
    fixed_versions: Optional[str] = None
    affected_assets_count: int
    affected_assets: List[AffectedServerItem] = []
    suggested_solution: str
    verification_command: Optional[str] = None
    match_type: str = "INVENTORY_PROACTIVE"
    confidence: str = "High"
    status: str = "Pending"  # Pending, Acknowledged, Remediated, False_Positive
    is_resolved: bool = False
    dispatched_telegram: bool = False
    date_detected: datetime
    updated_at: datetime


class PaginatedAlertsResponse(BaseModel):
    items: List[AlertItem]
    total: int
    page: int
    page_size: int
    total_pages: int
    critical_count: int = 0
    high_count: int = 0
    active_count: int = 0
    total_exposed_servers: int = 0


class AlertStatusUpdate(BaseModel):
    status: str  # "Pending", "Acknowledged", "Remediated", "False_Positive"
