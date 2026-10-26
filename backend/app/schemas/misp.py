from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class AffectedAssetDetail(BaseModel):
    asset_id: int
    server_name: Optional[str] = None
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    evidence: str
    installed_version: Optional[str] = None
    confidence: str
    recommended_verification: Optional[str] = None


class MispAssessmentReport(BaseModel):
    summary: str
    affected_assets: List[AffectedAssetDetail] = []
    recommended_actions: Optional[str] = None
    verification_command: Optional[str] = None
    matched_qid: Optional[int] = None


class MispAssessmentListItem(BaseModel):
    id: int
    misp_event_id: Optional[str] = None
    misp_event_date: Optional[datetime] = None
    cve_id: str
    source: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    affected_product: str
    vulnerable_versions: str
    fixed_versions: Optional[str] = None
    match_type: str
    confidence: str
    affected_assets_count: int
    dispatched_telegram: bool
    telegram_sent_at: Optional[datetime] = None
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MispAssessmentDetail(MispAssessmentListItem):
    assessment_report: Dict[str, Any] = {}


class PaginatedMispFeedResponse(BaseModel):
    items: List[MispAssessmentListItem]
    total: int
    total_events: Optional[int] = None
    page: int
    page_size: int
    total_pages: int
    pre_scan_count: int = 0
    confirmed_count: int = 0
    clean_count: int = 0


class MispSyncResponse(BaseModel):
    success: bool
    message: str
    assessments_run: int
    pre_scan_matches: int
    qualys_confirmed: int
    clean_cves: int


class MispStatusUpdate(BaseModel):
    status: str


class MispSummary(BaseModel):
    total_advisories: int
    total_events: Optional[int] = None
    pre_scan_matches: int
    qualys_confirmed: int
    at_risk_assets: int
    last_sync_time: Optional[str] = None
