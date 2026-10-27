from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AuditLogItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action: str
    target_type: str
    target_id: str
    target_name: Optional[str] = None
    actor_id: Optional[int] = None
    actor_username: str
    actor_role: str
    ip_address: Optional[str] = None
    details: Dict[str, Any] = {}
    created_at: datetime


class PaginatedAuditLogsResponse(BaseModel):
    items: List[AuditLogItem]
    total: int
    page: int
    page_size: int
    total_pages: int
