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

    # Recalculate parent asset's severity counts
    if asset:
        counts = RiskEngine.count_asset_severities(asset.detections)
        asset.total_vulns = counts["total"]
        asset.critical_vulns = counts["sev5"]
        asset.high_vulns = counts["sev4"]
        asset.medium_vulns = counts["sev3"]
        asset.low_vulns = counts["sev2"]
        asset.info_vulns = counts["sev1"]
        asset.risk_score = 0.0
        asset.risk_level = "Critical" if counts["sev5"] > 0 else "High" if counts["sev4"] > 0 else "Medium" if counts["sev3"] > 0 else "Low"
        asset.is_risky = (counts["sev5"] > 0)
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
