from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.schemas.detection import DetectionItem


class AssetListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    qualys_id: str
    server_name: Optional[str] = None
    ip_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    fqdn: Optional[str] = None
    netbios_name: Optional[str] = None
    os_name: Optional[str] = None
    os_family: Optional[str] = None
    tags: List[str] = []
    owner_id: Optional[int] = None
    owner_username: Optional[str] = None
    poc_name: Optional[str] = None
    poc_email: Optional[str] = None
    last_scan_date: Optional[datetime] = None
    risk_score: float = 0.0
    risk_level: str = "Low"
    is_risky: bool = False
    is_active: bool = True
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    info_vulns: int = 0


class AssetDetail(AssetListItem):
    detections: List[DetectionItem] = []


class PaginatedAssetsResponse(BaseModel):
    items: List[AssetListItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class AssetOwnerUpdate(BaseModel):
    owner_id: Optional[int] = None
    server_name: Optional[str] = None
    poc_name: Optional[str] = None
    poc_email: Optional[str] = None


class AssetDeleteRequest(BaseModel):
    reason: Optional[str] = None


class AssetDeleteResponse(BaseModel):
    success: bool
    message: str
    deleted_asset_id: int
    server_name: Optional[str] = None
    ip_address: Optional[str] = None


class AssetFilterParams(BaseModel):
    risk_level: Optional[str] = None
    is_risky: Optional[bool] = None
    is_active: Optional[bool] = None
    tag: Optional[str] = None
    os_family: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    page_size: int = 20
