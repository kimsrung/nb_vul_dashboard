from typing import List, Dict, Any
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, AsyncSessionLocal
from app.api.deps import require_viewer, require_admin
from app.models.user import User
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase
from app.models.alert import Alert
from app.models.misp_feed import MispCveAssessment
from app.models.setting import SystemSetting
from app.schemas.dashboard import (
    DashboardSummaryResponse,
    RiskDistribution,
    OSFamilyBreakdown,
    ThreatIntelBreakdown,
)
from app.schemas.asset import AssetListItem
from app.schemas.alert import AlertItem
from app.services.sync_service import SyncService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


async def bg_sync_task():
    async with AsyncSessionLocal() as session:
        await SyncService.run_sync(session, manual_trigger=True)


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    # Base filter for owner role
    is_owner = user.role == "owner"
    owner_asset_filter = [Asset.owner_id == user.id] if is_owner else []

    # Total and risky assets
    total_q = select(func.count(Asset.id))
    risky_q = select(func.count(Asset.id)).where(Asset.is_risky == True)
    if is_owner:
        total_q = total_q.where(Asset.owner_id == user.id)
        risky_q = risky_q.where(Asset.owner_id == user.id)

    total_assets = (await db.execute(total_q)).scalar() or 0
    risky_assets = (await db.execute(risky_q)).scalar() or 0

    # Risk distribution
    def dist_q(level):
        q = select(func.count(Asset.id)).where(Asset.risk_level == level)
        if is_owner:
            q = q.where(Asset.owner_id == user.id)
        return q

    crit_count = (await db.execute(dist_q("Critical"))).scalar() or 0
    high_count = (await db.execute(dist_q("High"))).scalar() or 0
    med_count = (await db.execute(dist_q("Medium"))).scalar() or 0
    low_count = (await db.execute(dist_q("Low"))).scalar() or 0

    # Active detections count
    vulns_q = select(func.count(Detection.id)).join(Asset, Asset.id == Detection.asset_id).where(
        Detection.status.in_(["Active", "New", "Re-Opened"]),
        Detection.remediation_status != "Resolved",
    )
    if is_owner:
        vulns_q = vulns_q.where(Asset.owner_id == user.id)

    total_vulns = (await db.execute(vulns_q)).scalar() or 0
    critical_vulns = (await db.execute(vulns_q.where(Detection.severity == 5))).scalar() or 0
    high_vulns = (await db.execute(vulns_q.where(Detection.severity == 4))).scalar() or 0

    # Active Proactive Alerts (FS-ISAC CVEs affecting asset inventory, pre-scan)
    alerts_q = select(MispCveAssessment).where(
        MispCveAssessment.match_type == "INVENTORY_PROACTIVE",
        MispCveAssessment.affected_assets_count > 0,
        MispCveAssessment.status.in_(["Pending", "Acknowledged"]),
    )
    all_advs = (await db.execute(alerts_q)).scalars().all()
    if is_owner:
        owned_asset_ids = set((await db.execute(select(Asset.id).where(Asset.owner_id == user.id))).scalars().all())
        active_alerts = sum(
            1 for adv in all_advs
            if any(a.get("asset_id") in owned_asset_ids for a in (adv.assessment_report or {}).get("affected_assets", []))
        )
    else:
        active_alerts = len(all_advs)

    # OS Breakdown
    os_q = (
        select(Asset.os_family, func.count(Asset.id))
        .group_by(Asset.os_family)
        .order_by(func.count(Asset.id).desc())
    )
    if is_owner:
        os_q = os_q.where(Asset.owner_id == user.id)
    os_res = await db.execute(os_q)
    top_os = [OSFamilyBreakdown(name=row[0] or "Unknown", count=row[1]) for row in os_res.all()]

    # Threat Intel / RTI flags across active detections
    ti_q = (
        select(KnowledgeBase.threat_intel_flags)
        .join(Detection, Detection.qid == KnowledgeBase.qid)
        .join(Asset, Asset.id == Detection.asset_id)
        .where(
            Detection.status.in_(["Active", "New", "Re-Opened"]),
            Detection.remediation_status != "Resolved",
        )
    )
    if is_owner:
        ti_q = ti_q.where(Asset.owner_id == user.id)

    ti_res = await db.execute(ti_q)
    ransomware_c = 0
    active_exp_c = 0
    public_exp_c = 0
    zero_day_c = 0

    for row in ti_res.scalars().all():
        if row:
            if row.get("ransomware"):
                ransomware_c += 1
            if row.get("active_in_wild") or row.get("exploit_in_wild"):
                active_exp_c += 1
            if row.get("exploit_public"):
                public_exp_c += 1
            if row.get("zero_day"):
                zero_day_c += 1

    # Recent risky assets
    recent_risky_q = select(Asset).where(Asset.is_risky == True)
    if is_owner:
        recent_risky_q = recent_risky_q.where(Asset.owner_id == user.id)
    recent_risky_q = recent_risky_q.order_by(Asset.risk_score.desc()).limit(5)
    recent_risky = (await db.execute(recent_risky_q)).scalars().all()

    # Recent proactive FS-ISAC alerts affecting inventory
    from app.api.routes.alerts import _map_assessment_to_alert
    proactive_recent_q = select(MispCveAssessment).where(
        MispCveAssessment.match_type == "INVENTORY_PROACTIVE",
        MispCveAssessment.affected_assets_count > 0,
    ).order_by(MispCveAssessment.created_at.desc()).limit(5)
    recent_assessments = (await db.execute(proactive_recent_q)).scalars().all()
    if is_owner:
        owned_asset_ids = set((await db.execute(select(Asset.id).where(Asset.owner_id == user.id))).scalars().all())
        recent_assessments = [
            adv for adv in recent_assessments
            if any(a.get("asset_id") in owned_asset_ids for a in (adv.assessment_report or {}).get("affected_assets", []))
        ]
    recent_alerts_items = [_map_assessment_to_alert(al) for al in recent_assessments]

    # Last sync time
    sync_setting = await db.get(SystemSetting, "last_sync_time")
    last_sync = sync_setting.value if sync_setting else None
    sync_status = await SyncService.get_sync_status()

    return DashboardSummaryResponse(
        total_assets=total_assets,
        risky_assets=risky_assets,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        active_alerts=active_alerts,
        sla_breaches=0,  # Included in risk score
        risk_distribution=RiskDistribution(
            critical=crit_count,
            high=high_count,
            medium=med_count,
            low=low_count,
        ),
        top_os_families=top_os,
        threat_intel_summary=ThreatIntelBreakdown(
            ransomware=ransomware_c,
            active_exploit=active_exp_c,
            public_exploit=public_exp_c,
            zero_day=zero_day_c,
        ),
        recent_risky_assets=[AssetListItem.model_validate(a) for a in recent_risky],
        recent_alerts=recent_alerts_items,
        last_sync_time=last_sync,
        sync_status=sync_status.get("status", "Idle"),
    )


@router.post("/sync")
async def trigger_manual_sync(
    background_tasks: BackgroundTasks,
    admin: User = Depends(require_admin),
):
    status = await SyncService.get_sync_status()
    if status.get("status") == "Syncing":
        return {"success": False, "message": "Sync is already in progress"}
    
    background_tasks.add_task(bg_sync_task)
    return {"success": True, "message": "Qualys data synchronization started in background"}


@router.get("/sync-status")
async def get_sync_status(user: User = Depends(require_viewer)):
    return await SyncService.get_sync_status()
