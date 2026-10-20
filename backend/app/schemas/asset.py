from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel
from app.schemas.detection import DetectionItem


class AssetListItem(BaseModel):
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
    last_scan_date: Optional[datetime] = None
    risk_score: float
    risk_level: str
    is_risky: bool
    total_vulns: int
    critical_vulns: int
    high_vulns: int

    class Config:
        from_attributes = True


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
    tag: Optional[str] = None
    os_family: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    page_size: int = 20
