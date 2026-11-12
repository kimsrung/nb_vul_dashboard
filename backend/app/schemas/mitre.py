from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class CompensatingControl(BaseModel):
    id: str  # e.g., "M1030"
    name: str  # e.g., "Network Segmentation"
    category: str  # "Network", "Configuration", "Access_Control", "Application_Shielding"
    description: str
    implementation_steps: List[str]
    downtime_required: bool = False
    applicable_platforms: List[str] = ["Linux", "Windows"]


class DetectionGuidance(BaseModel):
    log_sources: List[str]  # e.g., ["Web Access Logs", "Syslog / auth.log", "Auditd"]
    indicator_summary: str
    sample_query: Optional[str] = None
    event_ids: List[str] = []


class MitreTechnique(BaseModel):
    id: str  # e.g., "T1190"
    name: str  # e.g., "Exploit Public-Facing Application"
    tactic_id: str  # e.g., "TA0001"
    tactic_name: str  # e.g., "Initial Access"
    description: str
    adversary_perspective: str
    severity_impact: str  # "Critical", "High", "Medium", "Low"
    url: str
    compensating_controls: List[CompensatingControl] = []
    detection_guidance: Optional[DetectionGuidance] = None


class MitreTacticSummary(BaseModel):
    id: str  # e.g., "TA0001"
    name: str  # e.g., "Initial Access"
    short_name: str
    description: str
    kill_chain_order: int
    active_threats_count: int = 0
    affected_assets_count: int = 0
    critical_tier_exposure_count: int = 0  # Bakong, SWIFT, CBS
    techniques: List[MitreTechnique] = []


class MitreMatrixResponse(BaseModel):
    total_techniques_mapped: int
    tactics: List[MitreTacticSummary]
    top_critical_techniques: List[MitreTechnique]


class MitreTechniqueDetail(BaseModel):
    technique: MitreTechnique
    affected_assets: List[Dict[str, Any]] = []
    related_cves: List[str] = []
    related_qids: List[int] = []


class BankingTierReadiness(BaseModel):
    tier_name: str  # e.g., "Tier 1: Mission-Critical (Bakong, SWIFT, CBS)"
    tier_level: int  # 1, 2, 3
    total_assets: int
    clean_assets: int
    exposed_assets: int
    readiness_percentage: float
    critical_cves_count: int
    active_threats_count: int
    status: str  # "Optimal", "Good", "Requires_Attention", "Critical_Exposure"


class ThreatReadinessResponse(BaseModel):
    overall_readiness_score: float  # 0 to 100
    readiness_grade: str  # "Grade A (Optimal)", "Grade B (Good)", "Grade C (Attention Needed)", "Grade D (High Risk)"
    status_summary: str
    last_assessment_time: str
    tier_breakdown: List[BankingTierReadiness]
    mitre_coverage_percentage: float
    proactive_shield_rate: float  # % of threats with known compensating controls
    top_recommended_actions: List[Dict[str, Any]]
