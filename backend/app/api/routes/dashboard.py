from fastapi import APIRouter, Depends, BackgroundTasks, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, AsyncSessionLocal
from app.api.deps import require_viewer, require_admin
from app.models.user import User
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase
from app.models.misp_feed import MispCveAssessment
from app.models.setting import SystemSetting
from app.schemas.dashboard import (
    DashboardSummaryResponse,
    RiskDistribution,
    OSFamilyBreakdown,
    ThreatIntelBreakdown,
    SeverityBreakdown,
)
from app.schemas.asset import AssetListItem
from app.services.sync_service import SyncService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


async def bg_sync_task(mode: str = "delta"):
    async with AsyncSessionLocal() as session:
        await SyncService.run_sync(session, sync_mode=mode, manual_trigger=True)


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
    sev5_count = (await db.execute(vulns_q.where(Detection.severity == 5))).scalar() or 0
    sev4_count = (await db.execute(vulns_q.where(Detection.severity == 4))).scalar() or 0
    sev3_count = (await db.execute(vulns_q.where(Detection.severity == 3))).scalar() or 0
    sev2_count = (await db.execute(vulns_q.where(Detection.severity == 2))).scalar() or 0
    sev1_count = (await db.execute(vulns_q.where(Detection.severity == 1))).scalar() or 0
    critical_vulns = sev5_count
    high_vulns = sev4_count

    # MISP Threat Advisories & Matched Assets Count
    misp_all_q = select(MispCveAssessment)
    all_misp_advisories = (await db.execute(misp_all_q)).scalars().all()
    misp_advisories_count = len(all_misp_advisories)
    matched_asset_ids = set()
    for adv in all_misp_advisories:
        for aff in (adv.assessment_report or {}).get("affected_assets", []):
            if aff.get("asset_id"):
                matched_asset_ids.add(aff.get("asset_id"))
    misp_matched_assets_count = len(matched_asset_ids)

    # Active Threat Alerts (CVEs affecting asset inventory)
    alerts_q = select(MispCveAssessment).where(
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

    # Recent risky / most affected assets
    recent_risky_q = select(Asset).where(Asset.total_vulns > 0)
    if is_owner:
        recent_risky_q = recent_risky_q.where(Asset.owner_id == user.id)
    recent_risky_q = recent_risky_q.order_by(
        Asset.critical_vulns.desc(),
        Asset.high_vulns.desc(),
        Asset.total_vulns.desc(),
    ).limit(5)
    recent_risky = (await db.execute(recent_risky_q)).scalars().all()

    # Recent FS-ISAC alerts affecting inventory
    from app.api.routes.alerts import _map_assessment_to_alert
    recent_alerts_q = select(MispCveAssessment).where(
        MispCveAssessment.affected_assets_count > 0,
    ).order_by(MispCveAssessment.created_at.desc()).limit(5)
    recent_assessments = (await db.execute(recent_alerts_q)).scalars().all()
    if is_owner:
        owned_asset_ids = set((await db.execute(select(Asset.id).where(Asset.owner_id == user.id))).scalars().all())
        recent_assessments = [
            adv for adv in recent_assessments
            if any(a.get("asset_id") in owned_asset_ids for a in (adv.assessment_report or {}).get("affected_assets", []))
        ]
    recent_alerts_items = [_map_assessment_to_alert(al) for al in recent_assessments]

    # Sync metadata
    sync_setting = await db.get(SystemSetting, "last_sync_time")
    last_sync = sync_setting.value if sync_setting else None

    full_sync_setting = await db.get(SystemSetting, "qualys_last_full_sync_time")
    last_full_sync = full_sync_setting.value if full_sync_setting else None

    mode_setting = await db.get(SystemSetting, "qualys_last_sync_mode")
    last_mode = mode_setting.value if mode_setting else "delta"

    sync_status = await SyncService.get_sync_status()

    return DashboardSummaryResponse(
        total_assets=total_assets,
        risky_assets=risky_assets,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        severity_breakdown=SeverityBreakdown(
            sev5=sev5_count,
            sev4=sev4_count,
            sev3=sev3_count,
            sev2=sev2_count,
            sev1=sev1_count,
        ),
        misp_advisories_count=misp_advisories_count,
        misp_matched_assets_count=misp_matched_assets_count,
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
        last_full_sync_time=last_full_sync,
        last_sync_mode=last_mode,
        sync_status=sync_status.get("status", "Idle"),
    )


@router.post("/sync")
async def trigger_manual_sync(
    background_tasks: BackgroundTasks,
    mode: str = Query("delta", pattern="^(delta|full)$", description="Sync mode: 'delta' (quick incremental) or 'full' (complete reconciliation)"),
    admin: User = Depends(require_admin),
):
    status = await SyncService.get_sync_status()
    if status.get("status") == "Syncing":
        return {"success": False, "message": "Sync is already in progress"}
    
    background_tasks.add_task(bg_sync_task, mode)
    mode_label = "full reconciliation" if mode == "full" else "incremental delta"
    return {
        "success": True,
        "message": f"Qualys {mode_label} sync started in background",
        "sync_mode": mode,
    }


@router.get("/sync-status")
async def get_sync_status(user: User = Depends(require_viewer)):
    return await SyncService.get_sync_status()
