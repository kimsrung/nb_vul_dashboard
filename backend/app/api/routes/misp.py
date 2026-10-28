import logging
import math
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.api.deps import require_admin, require_analyst_or_admin
from app.models.user import User
from app.models.misp_feed import MispCveAssessment
from app.models.setting import SystemSetting
from app.schemas.misp import (
    MispAssessmentListItem,
    MispAssessmentDetail,
    MispSyncResponse,
    MispStatusUpdate,
    MispSummary,
    PaginatedMispFeedResponse,
)
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/misp", tags=["MISP Threat Intelligence"])


@router.get("/summary", response_model=MispSummary)
async def get_misp_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst_or_admin),
):
    """Retrieve KPI metrics for FS-ISAC threat intelligence advisories (Admin only)."""
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

    events_setting = await db.get(SystemSetting, "misp_total_events_count")
    total_events = int(events_setting.value) if events_setting and events_setting.value.isdigit() else (240 if not settings.MISP_MOCK_MODE else total_cnt)

    return MispSummary(
        total_advisories=total_cnt,
        total_events=total_events,
        pre_scan_matches=pre_scan_cnt,
        qualys_confirmed=qualys_cnt,
        at_risk_assets=len(all_affected_assets),
        last_sync_time=last_sync,
    )


@router.get("/feed", response_model=PaginatedMispFeedResponse)
async def list_misp_feed(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=200, description="Items per page"),
    search: Optional[str] = Query(None, description="Search by CVE ID, title, or affected product"),
    match_type: Optional[str] = Query(None, description="QUALYS_CONFIRMED | INVENTORY_PROACTIVE | NO_ASSETS_AFFECTED"),
    confidence: Optional[str] = Query(None, description="High | Medium | Low"),
    severity: Optional[str] = Query(None, description="Critical | High | Medium | Low"),
    source: Optional[str] = Query(None, description="Filter by publisher source (FS-ISAC, CIRCL, etc.)"),
    sort_by: Optional[str] = Query("cve_id", description="Sort by cve_id, misp_event_date, created_at, affected_assets_count, severity, cvss_score"),
    sort_order: Optional[str] = Query("desc", description="asc or desc"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst_or_admin),
):
    """List MISP threat intelligence CVE assessments with pagination, sorting, and filtering (Analyst or Admin)."""
    base_query = select(MispCveAssessment)

    if match_type:
        base_query = base_query.where(MispCveAssessment.match_type.ilike(match_type))
    if confidence:
        base_query = base_query.where(MispCveAssessment.confidence.ilike(f"%{confidence}%"))
    if severity:
        base_query = base_query.where(MispCveAssessment.severity.ilike(severity))
    if source:
        base_query = base_query.where(MispCveAssessment.source.ilike(f"%{source}%"))

    if search:
        s = f"%{search.strip()}%"
        base_query = base_query.where(
            or_(
                MispCveAssessment.cve_id.ilike(s),
                MispCveAssessment.title.ilike(s),
                MispCveAssessment.affected_product.ilike(s),
                MispCveAssessment.description.ilike(s),
            )
        )

    # Count total matching
    count_query = select(func.count()).select_from(base_query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    # Summary metrics across filtered set
    all_advs_res = await db.execute(base_query)
    all_advs = all_advs_res.scalars().all()
    pre_scan_cnt = sum(1 for a in all_advs if a.match_type == "INVENTORY_PROACTIVE")
    qualys_cnt = sum(1 for a in all_advs if a.match_type == "QUALYS_CONFIRMED")
    clean_cnt = sum(1 for a in all_advs if a.match_type == "NO_ASSETS_AFFECTED")

    # Sorting
    sort_col = MispCveAssessment.cve_id
    if sort_by == "affected_assets_count":
        sort_col = MispCveAssessment.affected_assets_count
    elif sort_by == "cve_id":
        sort_col = MispCveAssessment.cve_id
    elif sort_by == "title":
        sort_col = MispCveAssessment.title
    elif sort_by == "severity":
        sort_col = MispCveAssessment.severity
    elif sort_by == "cvss_score":
        sort_col = MispCveAssessment.cvss_score
    elif sort_by == "affected_product":
        sort_col = MispCveAssessment.affected_product
    elif sort_by == "match_type":
        sort_col = MispCveAssessment.match_type
    elif sort_by == "created_at":
        sort_col = MispCveAssessment.created_at
    elif sort_by == "misp_event_date":
        sort_col = MispCveAssessment.misp_event_date
    elif sort_by == "misp_event_id":
        sort_col = MispCveAssessment.misp_event_id
    elif sort_by == "source":
        sort_col = MispCveAssessment.source

    order_expr = sort_col.asc() if (sort_order or "").lower() == "asc" else sort_col.desc()
    skip = (page - 1) * page_size
    paged_query = base_query.order_by(order_expr, MispCveAssessment.id.desc()).offset(skip).limit(page_size)

    res = await db.execute(paged_query)
    items = res.scalars().all()
    total_pages = max(1, math.ceil(total / page_size))

    events_setting = await db.get(SystemSetting, "misp_total_events_count")
    total_events = int(events_setting.value) if events_setting and events_setting.value.isdigit() else (240 if not settings.MISP_MOCK_MODE else total)

    return PaginatedMispFeedResponse(
        items=items,
        total=total,
        total_events=total_events,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        pre_scan_count=pre_scan_cnt,
        confirmed_count=qualys_cnt,
        clean_count=clean_cnt,
    )


@router.get("/assessments/{assessment_id}", response_model=MispAssessmentDetail)
async def get_assessment_detail(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst_or_admin),
):
    """Retrieve full assessment report for an FS-ISAC CVE (Admin only)."""
    assessment = await db.get(MispCveAssessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return assessment


@router.post("/sync", response_model=MispSyncResponse)
async def sync_misp_fs_isac_feed(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
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

    # Record sync timestamp and total raw events count
    now_str = datetime.now().isoformat()
    sync_setting = await db.get(SystemSetting, "misp_last_sync_time")
    if sync_setting:
        sync_setting.value = now_str
    else:
        db.add(SystemSetting(key="misp_last_sync_time", value=now_str, description="Timestamp of last MISP FS-ISAC sync"))

    if getattr(client, "last_events_count", 0):
        events_setting = await db.get(SystemSetting, "misp_total_events_count")
        if events_setting:
            events_setting.value = str(client.last_events_count)
        else:
            db.add(SystemSetting(key="misp_total_events_count", value=str(client.last_events_count), description="Total raw MISP events fetched"))
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
