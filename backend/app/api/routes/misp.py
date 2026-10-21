import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.api.deps import require_viewer, require_analyst_or_admin
from app.models.user import User
from app.models.misp_feed import MispCveAssessment
from app.models.setting import SystemSetting
from app.schemas.misp import (
    MispAssessmentListItem,
    MispAssessmentDetail,
    MispSyncResponse,
    MispStatusUpdate,
    MispSummary,
)
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/misp", tags=["MISP Threat Intelligence"])


@router.get("/summary", response_model=MispSummary)
async def get_misp_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve KPI metrics for FS-ISAC threat intelligence advisories."""
    # Total advisories
    total_res = await db.execute(select(func.count(MispCveAssessment.id)))
    total_cnt = total_res.scalar() or 0

    # Pre-scan matches (proactive inventory matches before Qualys detection)
    pre_scan_res = await db.execute(
        select(func.count(MispCveAssessment.id)).where(MispCveAssessment.match_type == "INVENTORY_PROACTIVE")
    )
    pre_scan_cnt = pre_scan_res.scalar() or 0

    # Qualys scanner confirmed
    qualys_res = await db.execute(
        select(func.count(MispCveAssessment.id)).where(MispCveAssessment.match_type == "QUALYS_CONFIRMED")
    )
    qualys_cnt = qualys_res.scalar() or 0

    # Total at-risk assets affected across all pending/active advisories
    assessments_res = await db.execute(
        select(MispCveAssessment).where(MispCveAssessment.affected_assets_count > 0)
    )
    all_affected_assets = set()
    for row in assessments_res.scalars().all():
        assets_list = (row.assessment_report or {}).get("affected_assets", [])
        for a in assets_list:
            aid = a.get("asset_id")
            if aid:
                all_affected_assets.add(aid)

    # Last sync time
    sync_setting = await db.get(SystemSetting, "misp_last_sync_time")
    last_sync = sync_setting.value if sync_setting else None

    return MispSummary(
        total_advisories=total_cnt,
        pre_scan_matches=pre_scan_cnt,
        qualys_confirmed=qualys_cnt,
        at_risk_assets=len(all_affected_assets),
        last_sync_time=last_sync,
    )


@router.get("/feed", response_model=List[MispAssessmentListItem])
async def list_misp_feed(
    search: Optional[str] = Query(None, description="Search by CVE ID, title, or affected product"),
    match_type: Optional[str] = Query(None, description="QUALYS_CONFIRMED | INVENTORY_PROACTIVE | NO_ASSETS_AFFECTED"),
    confidence: Optional[str] = Query(None, description="High | Medium | Low"),
    severity: Optional[str] = Query(None, description="Critical | High | Medium | Low"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """List FS-ISAC CVE assessments with filtering."""
    query = select(MispCveAssessment)

    if match_type:
        query = query.where(MispCveAssessment.match_type == match_type)
    if confidence:
        query = query.where(MispCveAssessment.confidence.ilike(f"%{confidence}%"))
    if severity:
        query = query.where(MispCveAssessment.severity == severity)

    if search:
        s = f"%{search.strip()}%"
        query = query.where(
            or_(
                MispCveAssessment.cve_id.ilike(s),
                MispCveAssessment.title.ilike(s),
                MispCveAssessment.affected_product.ilike(s),
                MispCveAssessment.description.ilike(s),
            )
        )

    query = query.order_by(MispCveAssessment.affected_assets_count.desc(), MispCveAssessment.id.desc())
    res = await db.execute(query)
    return res.scalars().all()


@router.get("/assessments/{assessment_id}", response_model=MispAssessmentDetail)
async def get_assessment_detail(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve full assessment report for an FS-ISAC CVE."""
    assessment = await db.get(MispCveAssessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return assessment


@router.post("/sync", response_model=MispSyncResponse)
async def sync_misp_fs_isac_feed(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_analyst_or_admin),
):
    """Trigger ingestion from MISP (FS-ISAC feed) and execute proactive assessment against inventory."""
    client = MispClient()
    advisories = await client.fetch_fs_isac_events()

    if not advisories:
        return MispSyncResponse(
            success=True,
            message="No new FS-ISAC advisories fetched from MISP.",
            assessments_run=0,
            pre_scan_matches=0,
            qualys_confirmed=0,
            clean_cves=0,
        )

    assessments_run = 0
    pre_scan_matches = 0
    qualys_confirmed = 0
    clean_cves = 0

    for adv in advisories:
        record = await ProactiveAssessmentEngine.assess_cve(db, adv)
        assessments_run += 1
        if record.match_type == "INVENTORY_PROACTIVE":
            pre_scan_matches += 1
        elif record.match_type == "QUALYS_CONFIRMED":
            qualys_confirmed += 1
        else:
            clean_cves += 1

        # Dispatch Telegram alert for affected servers on Critical or High advisories
        if (
            settings.TELEGRAM_ENABLED
            and record.affected_assets_count > 0
            and (record.severity or "").upper() in ("CRITICAL", "HIGH")
        ):
            try:
                tg_text = TelegramService.format_misp_assessment_alert(record)
                await TelegramService.send_message(tg_text)
            except Exception as e:
                logger.error(f"Failed to dispatch Telegram alert for MISP assessment {record.cve_id}: {e}")

    # Record sync timestamp
    now_str = datetime.now().isoformat()
    sync_setting = await db.get(SystemSetting, "misp_last_sync_time")
    if sync_setting:
        sync_setting.value = now_str
    else:
        db.add(SystemSetting(key="misp_last_sync_time", value=now_str, description="Timestamp of last MISP FS-ISAC sync"))
    await db.commit()

    return MispSyncResponse(
        success=True,
        message=f"Synced {assessments_run} FS-ISAC advisories: {pre_scan_matches} proactive pre-scan matches, {qualys_confirmed} Qualys confirmed, {clean_cves} clean.",
        assessments_run=assessments_run,
        pre_scan_matches=pre_scan_matches,
        qualys_confirmed=qualys_confirmed,
        clean_cves=clean_cves,
    )


@router.post("/assessments/{assessment_id}/test-telegram")
async def dispatch_telegram_alert(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_analyst_or_admin),
):
    """Manually dispatch / test Telegram notification for an FS-ISAC assessment."""
    assessment = await db.get(MispCveAssessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    text = TelegramService.format_misp_assessment_alert(assessment)
    result = await TelegramService.send_message(text)
    if result.get("success"):
        assessment.dispatched_telegram = True
        assessment.telegram_sent_at = datetime.now()
        await db.commit()
    return result


@router.patch("/assessments/{assessment_id}/status", response_model=MispAssessmentListItem)
async def update_assessment_status(
    assessment_id: int,
    status_update: MispStatusUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_analyst_or_admin),
):
    """Update assessment remediation/acknowledgment status."""
    assessment = await db.get(MispCveAssessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    valid_statuses = ["Pending", "Acknowledged", "Remediated", "False_Positive"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    assessment.status = status_update.status
    await db.commit()
    await db.refresh(assessment)
    return assessment
