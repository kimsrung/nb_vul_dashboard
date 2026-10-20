from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class AlertItem(BaseModel):
    id: int
    asset_id: int
    alert_type: str
    title: str
    message: str
    severity: str
    is_resolved: bool
    dispatched_to_telegram: bool
    telegram_sent_at: Optional[datetime] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PaginatedAlertsResponse(BaseModel):
    items: List[AlertItem]
    total: int
    page: int
    page_size: int
    total_pages: int

