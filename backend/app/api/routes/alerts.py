import math
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
import json
from app.api.deps import require_viewer, require_analyst_or_admin, require_admin
from app.models.user import User
from app.models.asset import Asset
from app.models.misp_feed import MispCveAssessment
from app.models.setting import SystemSetting
from app.schemas.alert import (
    AlertItem,
    AffectedServerItem,
    PaginatedAlertsResponse,
    AlertStatusUpdate,
)
from app.services.audit_service import AuditService
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def _map_assessment_to_alert(a: MispCveAssessment) -> AlertItem:
    report = a.assessment_report or {}
    raw_affected = report.get("affected_assets", [])
    affected_items = []
    for s in raw_affected:
        affected_items.append(
            AffectedServerItem(
                asset_id=s.get("asset_id", 0),
                server_name=s.get("server_name"),
                ip_address=s.get("ip_address"),
                os_name=s.get("os_name"),
                owner_username=s.get("owner_username"),
                poc_name=s.get("poc_name"),
                poc_email=s.get("poc_email"),
                evidence=s.get("evidence", ""),
                installed_version=s.get("installed_version"),
                confidence=s.get("confidence", "High"),
                recommended_verification=s.get("recommended_verification"),
            )
        )

    solution = report.get("recommended_actions") or "Upgrade to the latest vendor patched release or apply recommended workarounds."
    verif_cmd = report.get("verification_command")

    misp_eid = str(report.get("misp_event_id") or a.id)

    return AlertItem(
        id=a.id,
        misp_event_id=misp_eid,
        cve_id=a.cve_id,
        source=a.source or "MISP",
        title=a.title,
        description=a.description,
        severity=a.severity,
        cvss_score=a.cvss_score,
        affected_product=a.affected_product,
        vulnerable_versions=a.vulnerable_versions,
        fixed_versions=a.fixed_versions,
        affected_assets_count=a.affected_assets_count,
        affected_assets=affected_items,
        suggested_solution=solution,
        verification_command=verif_cmd,
        match_type=a.match_type,
        confidence=a.confidence,
        status=a.status,
        is_resolved=a.status in ("Remediated", "Resolved"),
        dispatched_telegram=a.dispatched_telegram,
        date_detected=a.created_at,
        updated_at=a.updated_at,
    )


@router.get("", response_model=PaginatedAlertsResponse)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (Pending, Acknowledged, Remediated, False_Positive)"),
    is_resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low)"),
    match_type: Optional[str] = Query(None, description="Filter by match type (QUALYS_CONFIRMED, INVENTORY_PROACTIVE)"),
    search: Optional[str] = Query(None, description="Search by CVE ID, title, product, or server name"),
    sort_by: Optional[str] = Query("created_at", description="Sort by created_at, severity, affected_assets_count, cve_id"),
    sort_order: Optional[str] = Query("desc", description="Sort direction (asc, desc)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve FS-ISAC CVE threat alerts affecting the asset inventory.
    Includes both Qualys scanner confirmed detections and proactive pre-scan matches.
    """
    # Query FS-ISAC matches that affect asset inventory
    base_query = select(MispCveAssessment).where(
        MispCveAssessment.affected_assets_count > 0,
    )
    if match_type:
        base_query = base_query.where(MispCveAssessment.match_type.ilike(match_type))

    if status_filter:
        base_query = base_query.where(MispCveAssessment.status.ilike(status_filter))
    elif is_resolved is not None:
        if is_resolved:
            base_query = base_query.where(MispCveAssessment.status.in_(["Remediated", "Resolved"]))
        else:
            base_query = base_query.where(~MispCveAssessment.status.in_(["Remediated", "Resolved"]))

    if severity:
        base_query = base_query.where(MispCveAssessment.severity.ilike(severity))

    if search:
        s_term = f"%{search.strip()}%"
        base_query = base_query.where(
            or_(
                MispCveAssessment.cve_id.ilike(s_term),
                MispCveAssessment.title.ilike(s_term),
                MispCveAssessment.affected_product.ilike(s_term),
                MispCveAssessment.description.ilike(s_term),
            )
        )

    # Scoping for owner role: only include alerts that affect servers owned by this user
    if user.role == "owner":
        owned_assets_res = await db.execute(select(Asset.id).where(Asset.owner_id == user.id))
        owned_ids = set(owned_assets_res.scalars().all())

        # Filter assessments in memory by owned asset IDs
        all_matches_res = await db.execute(base_query)
        all_matches = all_matches_res.scalars().all()
        scoped_matches = []
        for adv in all_matches:
            adv_asset_ids = [a.get("asset_id") for a in (adv.assessment_report or {}).get("affected_assets", [])]
            if any(aid in owned_ids for aid in adv_asset_ids):
                scoped_matches.append(adv)

        total = len(scoped_matches)
        # Compute summary metrics
        crit_cnt = sum(1 for a in scoped_matches if a.severity == "Critical")
        high_cnt = sum(1 for a in scoped_matches if a.severity == "High")
        active_cnt = sum(1 for a in scoped_matches if a.status not in ("Remediated", "Resolved"))
        exposed_servers_set = set()
        for a in scoped_matches:
            for s in (a.assessment_report or {}).get("affected_assets", []):
                aid = s.get("asset_id")
                if aid in owned_ids:
                    exposed_servers_set.add(aid)

        # Sort
        reverse = (sort_order or "desc").lower() == "desc"
        if sort_by == "severity":
            rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            scoped_matches.sort(key=lambda x: rank.get(x.severity, 0), reverse=reverse)
        elif sort_by == "affected_assets_count":
            scoped_matches.sort(key=lambda x: x.affected_assets_count, reverse=reverse)
        elif sort_by == "cve_id":
            scoped_matches.sort(key=lambda x: x.cve_id.lower(), reverse=reverse)
        elif sort_by == "id":
            scoped_matches.sort(key=lambda x: x.id, reverse=reverse)
        elif sort_by == "title":
            scoped_matches.sort(key=lambda x: (x.title or "").lower(), reverse=reverse)
        elif sort_by == "match_type":
            scoped_matches.sort(key=lambda x: (x.match_type or "").lower(), reverse=reverse)
        elif sort_by == "status":
            scoped_matches.sort(key=lambda x: (x.status or "").lower(), reverse=reverse)
        else:
            scoped_matches.sort(key=lambda x: x.created_at, reverse=reverse)

        skip = (page - 1) * page_size
        paged_items = scoped_matches[skip : skip + page_size]
        total_pages = max(1, math.ceil(total / page_size))

        return PaginatedAlertsResponse(
            items=[_map_assessment_to_alert(a) for a in paged_items],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            critical_count=crit_cnt,
            high_count=high_cnt,
            active_count=active_cnt,
            total_exposed_servers=len(exposed_servers_set),
        )

    # General / Admin / Analyst access
    count_query = select(func.count()).select_from(base_query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    # Summary metrics across all matching
    all_advs_res = await db.execute(base_query)
    all_advs = all_advs_res.scalars().all()
    crit_cnt = sum(1 for a in all_advs if a.severity == "Critical")
    high_cnt = sum(1 for a in all_advs if a.severity == "High")
    active_cnt = sum(1 for a in all_advs if a.status not in ("Remediated", "Resolved"))
    exposed_servers_set = set()
    for a in all_advs:
        for s in (a.assessment_report or {}).get("affected_assets", []):
            aid = s.get("asset_id")
            if aid:
                exposed_servers_set.add(aid)

    # Sort
    order_col = MispCveAssessment.created_at
    if sort_by == "affected_assets_count":
        order_col = MispCveAssessment.affected_assets_count
    elif sort_by == "cve_id":
        order_col = MispCveAssessment.cve_id
    elif sort_by == "title":
        order_col = MispCveAssessment.title
    elif sort_by == "id":
        order_col = MispCveAssessment.id
    elif sort_by == "severity":
        order_col = MispCveAssessment.severity
    elif sort_by == "match_type":
        order_col = MispCveAssessment.match_type
    elif sort_by == "status":
        order_col = MispCveAssessment.status

    order_expr = order_col.asc() if (sort_order or "").lower() == "asc" else order_col.desc()
    skip = (page - 1) * page_size
    paged_query = base_query.order_by(order_expr, MispCveAssessment.id.desc()).offset(skip).limit(page_size)

    res = await db.execute(paged_query)
    items = res.scalars().all()
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedAlertsResponse(
        items=[_map_assessment_to_alert(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        critical_count=crit_cnt,
        high_count=high_cnt,
        active_count=active_cnt,
        total_exposed_servers=len(exposed_servers_set),
    )


@router.patch("/{alert_id}/status", response_model=AlertItem)
@router.post("/{alert_id}/resolve", response_model=AlertItem)
async def update_alert_status(
    alert_id: int,
    request: Request,
    status_update: Optional[AlertStatusUpdate] = None,
    db: AsyncSession = Depends(get_db),
    admin_or_analyst: User = Depends(require_analyst_or_admin),
):
    """Update alert remediation status (Pending, Acknowledged, Remediated, False_Positive)."""
    assessment = await db.get(MispCveAssessment, alert_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    new_status = status_update.status if status_update else "Remediated"
    old_status = assessment.status
    assessment.status = new_status
    assessment.updated_at = datetime.now(timezone.utc)

    # Log to audit history
    await AuditService.log_event(
        db=db,
        action="UPDATE_ALERT_STATUS",
        target_type="Alert",
        target_id=str(assessment.id),
        target_name=f"{assessment.cve_id} ({assessment.affected_product})",
        actor=admin_or_analyst,
        request=request,
        details={
            "alert_id": assessment.id,
            "cve_id": assessment.cve_id,
            "old_status": old_status,
            "new_status": new_status,
            "severity": assessment.severity,
        },
    )

    await db.commit()
    return _map_assessment_to_alert(assessment)


@router.get("/{alert_id}", response_model=AlertItem)
async def get_alert_detail(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve full detail for a specific threat alert assessment."""
    assessment = await db.get(MispCveAssessment, alert_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    return _map_assessment_to_alert(assessment)


@router.post("/{alert_id}/telegram")
async def dispatch_telegram_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_analyst_or_admin),
):
    """Manually dispatch / test Telegram notification for a threat alert."""
    assessment = await db.get(MispCveAssessment, alert_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    text = TelegramService.format_misp_assessment_alert(assessment)
    result = await TelegramService.send_message(text)
    if result.get("success"):
        assessment.dispatched_telegram = True
        assessment.telegram_sent_at = datetime.now(timezone.utc)
        await db.commit()
    return result


@router.post("/simulate-event")
async def simulate_threat_event(
    request: Request,
    admin: User = Depends(require_admin),
):
    """Simulate a real-time ZeroMQ threat event from MISP and evaluate against inventory."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")

    from app.services.misp_zmq_subscriber import process_misp_zmq_payload
    await process_misp_zmq_payload("misp_json_event", json.dumps(body))
    return {
        "success": True,
        "message": "ZeroMQ threat event processed and verified against asset inventory!",
    }
