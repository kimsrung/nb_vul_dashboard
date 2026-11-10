import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer
from app.models.user import User
from app.schemas.mitre import (
    MitreMatrixResponse,
    MitreTechniqueDetail,
    MitreTechnique,
)
from app.services.mitre_service import MitreService, TECHNIQUES_CATALOG

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("/matrix", response_model=MitreMatrixResponse)
async def get_mitre_matrix(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve the 14 MITRE Enterprise Tactics matrix with active threat counts,

    affected asset tallies, and critical banking tier exposures.
    """
    return await MitreService.get_mitre_matrix(db)


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueDetail)
async def get_technique_detail(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve in-depth adversary perspective, actionable compensating controls,

    detection guidance, and affected banking assets for a specific technique (e.g. T1190).
    """
    detail = await MitreService.get_technique_detail(db, technique_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found in catalog",
        )
    return detail


@router.get("/lookup", response_model=List[MitreTechnique])
async def lookup_mitre_techniques(
    cve: Optional[str] = Query(None, description="CVE ID (e.g. CVE-2024-6387)"),
    title: Optional[str] = Query(None, description="Vulnerability title or product name"),
    user: User = Depends(require_viewer),
):
    """Correlate a CVE or vulnerability description to relevant MITRE ATT&CK techniques."""
    cve_list = [cve.strip()] if cve else []
    return MitreService.map_to_techniques(
        title=title or "",
        cve_list=cve_list,
        product=title or "",
    )
