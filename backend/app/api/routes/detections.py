from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import get_current_user, require_viewer
from app.models.user import User
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase
from app.schemas.detection import DetectionItem, RemediationUpdate
from app.services.risk_engine import RiskEngine
from app.services.audit_service import AuditService

router = APIRouter(prefix="/detections", tags=["Detections & Remediation"])


@router.get("/{detection_id}", response_model=DetectionItem)
async def get_detection(
    detection_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    query = (
        select(Detection)
        .options(selectinload(Detection.knowledge_base))
        .where(Detection.id == detection_id)
    )
    res = await db.execute(query)
    det = res.scalar_one_or_none()
    if not det:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} not found",
        )
    return det


@router.patch("/{detection_id}/remediation", response_model=DetectionItem)
async def update_remediation(
    detection_id: int,
    remediation_in: RemediationUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    valid_statuses = ["Open", "In_Progress", "Acknowledged", "False_Positive", "Resolved"]
    if remediation_in.remediation_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid remediation status. Must be one of: {', '.join(valid_statuses)}",
        )

    query = (
        select(Detection)
        .options(selectinload(Detection.knowledge_base))
        .where(Detection.id == detection_id)
    )
    res = await db.execute(query)
    det = res.scalar_one_or_none()
    if not det:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} not found",
        )

    old_status = det.remediation_status

    # Check authorization: Admin, Analyst, or Asset Owner
    asset_res = await db.execute(
        select(Asset)
        .options(selectinload(Asset.detections))
        .where(Asset.id == det.asset_id)
    )
    asset = asset_res.scalar_one_or_none()

    if user.role == "viewer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read-only viewers cannot update remediation status",
        )
    if user.role == "owner" and (not asset or asset.owner_id != user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are only authorized to remediate assets assigned to you",
        )

    now = datetime.now(timezone.utc)
    det.remediation_status = remediation_in.remediation_status
    if remediation_in.remediation_notes is not None:
        det.remediation_notes = remediation_in.remediation_notes
    det.updated_by = user.username
    det.updated_at = now

    await db.flush()

    # Recalculate parent asset's risk score
    if asset:
        # Load KB entries for these detections
        qids = [d.qid for d in asset.detections]
        kb_res = await db.execute(select(KnowledgeBase).where(KnowledgeBase.qid.in_(qids)))
        kb_map = {kb.qid: kb for kb in kb_res.scalars().all()}

        score, risk_lvl, is_risky, total_v, crit_v, high_v = RiskEngine.calculate_asset_risk(
            asset.detections, kb_map, now=now
        )
        asset.risk_score = score
        asset.risk_level = risk_lvl
        asset.is_risky = is_risky
        asset.total_vulns = total_v
        asset.critical_vulns = crit_v
        asset.high_vulns = high_v
        asset.updated_at = now

    # Audit log remediation update
    await AuditService.log_event(
        db=db,
        action="UPDATE_REMEDIATION",
        target_type="Detection",
        target_id=str(detection_id),
        target_name=f"QID {det.qid}: {det.knowledge_base.title if det.knowledge_base else 'Vulnerability'}",
        actor=user,
        request=request,
        details={
            "detection_id": det.id,
            "qid": det.qid,
            "asset_id": det.asset_id,
            "old_status": old_status,
            "new_status": det.remediation_status,
            "notes": det.remediation_notes,
            "server_name": asset.server_name if asset else None,
            "ip_address": asset.ip_address if asset else None,
        },
    )

    await db.commit()
    await db.refresh(det)
    return det
