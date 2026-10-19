from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class KnowledgeBaseItem(BaseModel):
    qid: int
    title: str
    category: Optional[str] = None
    vuln_type: Optional[str] = None
    severity: int
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    diagnosis: Optional[str] = None
    consequence: Optional[str] = None
    solution: Optional[str] = None
    patches: Optional[List[Dict[str, Any]]] = None
    workaround: Optional[str] = None
    cve_list: Optional[List[str]] = None
    threat_intel_flags: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
