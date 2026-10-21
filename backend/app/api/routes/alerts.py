import math
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.api.deps import require_viewer, require_analyst_or_admin
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
                evidence=s.get("evidence", ""),
                installed_version=s.get("installed_version"),
                confidence=s.get("confidence", "High"),
                recommended_verification=s.get("recommended_verification"),
            )
        )

    solution = report.get("recommended_actions") or "Upgrade to the latest vendor patched release or apply recommended workarounds."
    verif_cmd = report.get("verification_command")

    return AlertItem(
        id=a.id,
        cve_id=a.cve_id,
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
    search: Optional[str] = Query(None, description="Search by CVE ID, title, product, or server name"),
    sort_by: Optional[str] = Query("created_at", description="Sort by created_at, severity, affected_assets_count, cve_id"),
    sort_order: Optional[str] = Query("desc", description="Sort direction (asc, desc)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Retrieve proactive FS-ISAC CVE threat alerts affecting the asset inventory.
    Excludes CVEs already detected by the Qualys scanner.
    """
    # Strictly query FS-ISAC proactive matches that affect asset inventory
    base_query = select(MispCveAssessment).where(
        MispCveAssessment.match_type == "INVENTORY_PROACTIVE",
        MispCveAssessment.affected_assets_count > 0,
    )

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


@router.post("/sync")
async def sync_misp_and_assess(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_or_analyst: User = Depends(require_analyst_or_admin),
):
    """Trigger on-demand fetch from MISP (FS-ISAC) and proactive inventory matching."""
    settings_res = await db.execute(select(SystemSetting))
    for row in settings_res.scalars().all():
        k, v = row.key, row.value
        if k == "misp_url" and v:
            settings.MISP_URL = v
        elif k == "misp_api_key" and v:
            settings.MISP_API_KEY = v
        elif k == "misp_creator_org" and v:
            settings.MISP_CREATOR_ORG = v
        elif k == "misp_tag_filter" and v:
            settings.MISP_TAG_FILTER = v
        elif k == "misp_mock_mode":
            settings.MISP_MOCK_MODE = v.lower() in ("true", "1")

    client = MispClient(
        base_url=settings.MISP_URL,
        api_key=settings.MISP_API_KEY,
        creator_org=settings.MISP_CREATOR_ORG,
        tag_filter=settings.MISP_TAG_FILTER,
        mock_mode=settings.MISP_MOCK_MODE,
    )
    advisories = await client.fetch_fs_isac_events()

    if not advisories:
        return {
            "success": True,
            "message": "No new FS-ISAC advisories fetched from MISP.",
            "alerts_created": 0,
        }

    alerts_created = 0
    qualys_confirmed = 0
    clean_count = 0

    for adv in advisories:
        record = await ProactiveAssessmentEngine.assess_cve(db, adv)
        if record.match_type == "INVENTORY_PROACTIVE" and record.affected_assets_count > 0:
            alerts_created += 1
            if (
                settings.TELEGRAM_ENABLED
                and (record.severity or "").upper() in ("CRITICAL", "HIGH")
                and not record.dispatched_telegram
            ):
                try:
                    tg_text = TelegramService.format_misp_assessment_alert(record)
                    await TelegramService.send_message(tg_text)
                    record.dispatched_telegram = True
                except Exception as te:
                    logger.error(f"Telegram dispatch failed: {te}")
        elif record.match_type == "QUALYS_CONFIRMED":
            qualys_confirmed += 1
        else:
            clean_count += 1

    now_str = datetime.now(timezone.utc).isoformat()
    sync_setting = await db.get(SystemSetting, "misp_last_sync_time")
    if sync_setting:
        sync_setting.value = now_str
    else:
        db.add(SystemSetting(key="misp_last_sync_time", value=now_str, description="Timestamp of last MISP FS-ISAC sync"))

    await db.commit()

    return {
        "success": True,
        "message": f"Synced {len(advisories)} FS-ISAC advisories: {alerts_created} active proactive alerts, {qualys_confirmed} already scanned by Qualys, {clean_count} clean.",
        "alerts_created": alerts_created,
        "qualys_confirmed": qualys_confirmed,
        "clean_count": clean_count,
    }


@router.post("/misp-push")
async def misp_push_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Webhook endpoint for MISP to push newly published CVE advisories in real-time."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")

    raw_events = []
    if isinstance(body, list):
        raw_events = body
    elif isinstance(body, dict):
        if "response" in body:
            raw_events = body["response"]
        elif "Event" in body:
            raw_events = [body]
        else:
            raw_events = [body]

    client = MispClient()
    parsed_advisories = client._parse_misp_events(raw_events)
    if not parsed_advisories:
        return {
            "success": True,
            "message": "Payload received but did not match FS-ISAC Creator Org or vulnerability:CVE tags.",
            "alerts_created": 0,
        }

    alerts_created = 0
    for adv in parsed_advisories:
        record = await ProactiveAssessmentEngine.assess_cve(db, adv)
        if record.match_type == "INVENTORY_PROACTIVE" and record.affected_assets_count > 0:
            alerts_created += 1
            if (
                settings.TELEGRAM_ENABLED
                and (record.severity or "").upper() in ("CRITICAL", "HIGH")
                and not record.dispatched_telegram
            ):
                try:
                    tg_text = TelegramService.format_misp_assessment_alert(record)
                    await TelegramService.send_message(tg_text)
                    record.dispatched_telegram = True
                except Exception as e:
                    logger.error(f"Telegram dispatch failed: {e}")

    await db.commit()

    return {
        "success": True,
        "message": f"Processed {len(parsed_advisories)} advisories from push webhook. {alerts_created} new proactive alert(s) logged in Alert Center.",
        "alerts_created": alerts_created,
    }
