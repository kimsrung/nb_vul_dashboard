from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.schemas.knowledge_base import KnowledgeBaseItem


class DetectionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    qid: int
    detection_type: str
    severity: int
    status: str
    first_found_date: Optional[datetime] = None
    last_found_date: Optional[datetime] = None
    times_found: int = 1
    port: Optional[int] = None
    protocol: Optional[str] = None
    scanner_results: Optional[str] = None
    remediation_status: str
    remediation_notes: Optional[str] = None
    updated_by: Optional[str] = None
    knowledge_base: Optional[KnowledgeBaseItem] = None


class RemediationUpdate(BaseModel):
    remediation_status: str  # "Open" | "In_Progress" | "Acknowledged" | "False_Positive" | "Resolved"
    remediation_notes: Optional[str] = None
