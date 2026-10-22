from typing import List, Optional
from pydantic import BaseModel
from app.schemas.asset import AssetListItem
from app.schemas.alert import AlertItem


class RiskDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class OSFamilyBreakdown(BaseModel):
    name: str
    count: int


class ThreatIntelBreakdown(BaseModel):
    ransomware: int = 0
    active_exploit: int = 0
    public_exploit: int = 0
    zero_day: int = 0


class DashboardSummaryResponse(BaseModel):
    total_assets: int
    risky_assets: int
    total_vulns: int
    critical_vulns: int
    high_vulns: int
    active_alerts: int
    sla_breaches: int
    risk_distribution: RiskDistribution
    top_os_families: List[OSFamilyBreakdown]
    threat_intel_summary: ThreatIntelBreakdown
    recent_risky_assets: List[AssetListItem]
    recent_alerts: List[AlertItem]
    last_sync_time: Optional[str] = None
    last_full_sync_time: Optional[str] = None
    last_sync_mode: Optional[str] = None
    sync_status: str = "Idle"
