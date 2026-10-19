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
    # Total and risky assets
    total_assets_res = await db.execute(select(func.count(Asset.id)))
    total_assets = total_assets_res.scalar() or 0

    risky_assets_res = await db.execute(select(func.count(Asset.id)).where(Asset.is_risky == True))
    risky_assets = risky_assets_res.scalar() or 0

    # Risk distribution
    crit_count = (await db.execute(select(func.count(Asset.id)).where(Asset.risk_level == "Critical"))).scalar() or 0
    high_count = (await db.execute(select(func.count(Asset.id)).where(Asset.risk_level == "High"))).scalar() or 0
    med_count = (await db.execute(select(func.count(Asset.id)).where(Asset.risk_level == "Medium"))).scalar() or 0
    low_count = (await db.execute(select(func.count(Asset.id)).where(Asset.risk_level == "Low"))).scalar() or 0

    # Active detections count
    active_vulns_res = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.status.in_(["Active", "New", "Re-Opened"]),
            Detection.remediation_status != "Resolved",
        )
    )
    total_vulns = active_vulns_res.scalar() or 0

    crit_vulns_res = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.status.in_(["Active", "New", "Re-Opened"]),
            Detection.severity == 5,
            Detection.remediation_status != "Resolved",
        )
    )
    critical_vulns = crit_vulns_res.scalar() or 0

    high_vulns_res = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.status.in_(["Active", "New", "Re-Opened"]),
            Detection.severity == 4,
            Detection.remediation_status != "Resolved",
        )
    )
    high_vulns = high_vulns_res.scalar() or 0

    # Active Alerts
    active_alerts_res = await db.execute(
        select(func.count(Alert.id)).where(Alert.is_resolved == False)
    )
    active_alerts = active_alerts_res.scalar() or 0

    # OS Breakdown
    os_res = await db.execute(
        select(Asset.os_family, func.count(Asset.id))
        .group_by(Asset.os_family)
        .order_by(func.count(Asset.id).desc())
    )
    top_os = [OSFamilyBreakdown(name=row[0] or "Unknown", count=row[1]) for row in os_res.all()]

    # Threat Intel / RTI flags across active detections
    ti_res = await db.execute(
        select(KnowledgeBase.threat_intel_flags)
        .join(Detection, Detection.qid == KnowledgeBase.qid)
        .where(
            Detection.status.in_(["Active", "New", "Re-Opened"]),
            Detection.remediation_status != "Resolved",
        )
    )
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
    recent_risky_res = await db.execute(
        select(Asset)
        .where(Asset.is_risky == True)
        .order_by(Asset.risk_score.desc())
        .limit(5)
    )
    recent_risky = recent_risky_res.scalars().all()

    # Recent alerts
    recent_alerts_res = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(5)
    )
    recent_alerts = recent_alerts_res.scalars().all()

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
        recent_risky_assets=[AssetListItem.from_orm(a) for a in recent_risky],
        recent_alerts=[AlertItem.from_orm(al) for al in recent_alerts],
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
