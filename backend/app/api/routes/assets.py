import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy import select, func, or_, String
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer, require_analyst_or_admin, require_admin
from app.models.user import User
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.knowledge_base import KnowledgeBase
from app.models.misp_feed import MispCveAssessment
from app.schemas.asset import (
    AssetListItem,
    AssetDetail,
    PaginatedAssetsResponse,
    AssetOwnerUpdate,
    AssetDeleteRequest,
    AssetDeleteResponse,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=PaginatedAssetsResponse)
async def list_assets(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (Critical, High, Medium, Low)"),
    is_risky: Optional[bool] = Query(None, description="Filter flagged risky assets"),
    is_active: Optional[bool] = Query(None, description="Filter active or decommissioned assets"),
    server_name: Optional[str] = Query(None, description="Filter by server name"),
    os_family: Optional[str] = Query(None, description="Filter by OS family"),
    owner_id: Optional[int] = Query(None, description="Filter by owner ID"),
    search: Optional[str] = Query(None, description="Search by Server Name, IP, FQDN, or OS"),
    cve: Optional[str] = Query(None, description="Filter by CVE ID (e.g. CVE-2024-6387, CVE-2020-11022)"),
    sort_by: Optional[str] = Query(None, description="Sort column (host_ip, server_name, os, owner, vulns, risk, scanned)"),
    sort_order: Optional[str] = Query("desc", description="Sort direction (asc, desc)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    base_query = select(Asset)

    # RBAC Scoping: "owner" role can only see their own assigned assets
    if user.role == "owner":
        base_query = base_query.where(Asset.owner_id == user.id)
    elif owner_id is not None:
        base_query = base_query.where(Asset.owner_id == owner_id)

    if risk_level:
        base_query = base_query.where(Asset.risk_level == risk_level)
    if is_risky is not None:
        base_query = base_query.where(Asset.is_risky == is_risky)
    if is_active is not None:
        base_query = base_query.where(Asset.is_active == is_active)
    if os_family:
        base_query = base_query.where(Asset.os_family == os_family)
    if server_name:
        base_query = base_query.where(Asset.server_name.ilike(f"%{server_name}%"))

    # Dedicated CVE Filter
    if cve and cve.strip():
        cve_clean = cve.strip().upper()
        cve_pattern = f"%{cve_clean}%"
        
        # Qualys scanner detections with KB matching this CVE
        kb_cve_subq = (
            select(Detection.asset_id)
            .distinct()
            .join(KnowledgeBase, KnowledgeBase.qid == Detection.qid)
            .where(
                or_(
                    func.cast(KnowledgeBase.cve_list, String).ilike(cve_pattern),
                    KnowledgeBase.title.ilike(cve_pattern),
                )
            )
        )
        
        # MISP proactive assessments affecting assets
        misp_cve_q = select(MispCveAssessment).where(MispCveAssessment.cve_id.ilike(cve_pattern))
        misp_cve_res = await db.execute(misp_cve_q)
        misp_asset_ids = set()
        for adv in misp_cve_res.scalars().all():
            for a in (adv.assessment_report or {}).get("affected_assets", []):
                aid = a.get("asset_id")
                if aid:
                    misp_asset_ids.add(aid)

        if misp_asset_ids:
            base_query = base_query.where(
                or_(
                    Asset.id.in_(kb_cve_subq),
                    Asset.id.in_(list(misp_asset_ids)),
                )
            )
        else:
            base_query = base_query.where(Asset.id.in_(kb_cve_subq))

    if search:
        s_clean = search.strip()
        search_filter = f"%{s_clean}%"
        search_conditions = [
            Asset.server_name.ilike(search_filter),
            Asset.ip_address.ilike(search_filter),
            Asset.fqdn.ilike(search_filter),
            Asset.os_name.ilike(search_filter),
            Asset.netbios_name.ilike(search_filter),
            Asset.owner_username.ilike(search_filter),
            Asset.poc_name.ilike(search_filter),
            Asset.poc_email.ilike(search_filter),
        ]

        # If search query looks like a CVE, also match assets having that CVE
        if "CVE" in s_clean.upper() or ("-" in s_clean and any(c.isdigit() for c in s_clean)):
            cve_search_subq = (
                select(Detection.asset_id)
                .distinct()
                .join(KnowledgeBase, KnowledgeBase.qid == Detection.qid)
                .where(
                    or_(
                        func.cast(KnowledgeBase.cve_list, String).ilike(search_filter),
                        KnowledgeBase.title.ilike(search_filter),
                    )
                )
            )
            search_conditions.append(Asset.id.in_(cve_search_subq))

        base_query = base_query.where(or_(*search_conditions))

    # Count total
    count_query = select(func.count()).select_from(base_query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    # Paginate and sort
    skip = (page - 1) * page_size

    order_col = Asset.critical_vulns
    if sort_by in ("host_ip", "ip_address"):
        order_col = Asset.ip_address
    elif sort_by == "server_name":
        order_col = Asset.server_name
    elif sort_by in ("os", "os_name"):
        order_col = Asset.os_name
    elif sort_by in ("owner", "owner_username"):
        order_col = Asset.owner_username
    elif sort_by in ("poc", "poc_name"):
        order_col = Asset.poc_name
    elif sort_by in ("vulns", "crit_vulns", "critical_vulns", "sev5"):
        order_col = Asset.critical_vulns
    elif sort_by in ("high_vulns", "sev4"):
        order_col = Asset.high_vulns
    elif sort_by in ("medium_vulns", "sev3"):
        order_col = Asset.medium_vulns
    elif sort_by == "total_vulns":
        order_col = Asset.total_vulns
    elif sort_by in ("scanned", "last_scan_date"):
        order_col = Asset.last_scan_date
    elif sort_by == "risk":
        order_col = Asset.critical_vulns

    order_expr = order_col.asc() if (sort_order or "").lower() == "asc" else order_col.desc()
    query = base_query.order_by(order_expr, Asset.id.asc()).offset(skip).limit(page_size)

    res = await db.execute(query)
    items = res.scalars().all()
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedAssetsResponse(
        items=[AssetListItem.model_validate(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset_detail(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    query = (
        select(Asset)
        .options(
            selectinload(Asset.detections).selectinload(Detection.knowledge_base)
        )
        .where(Asset.id == asset_id)
    )
    res = await db.execute(query)
    asset = res.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found",
        )

    # RBAC Scoping: "owner" role cannot inspect assets belonging to others
    if user.role == "owner" and asset.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this asset dossier",
        )

    return asset


@router.patch("/{asset_id}/owner", response_model=AssetListItem)
async def update_asset_owner(
    asset_id: int,
    update_data: AssetOwnerUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_or_analyst: User = Depends(require_analyst_or_admin),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found",
        )

    old_owner = asset.owner_username
    old_server_name = asset.server_name
    old_poc_name = asset.poc_name
    old_poc_email = asset.poc_email

    if update_data.server_name is not None:
        asset.server_name = update_data.server_name.strip()

    if update_data.poc_name is not None:
        asset.poc_name = update_data.poc_name.strip() if update_data.poc_name.strip() else None

    if update_data.poc_email is not None:
        asset.poc_email = update_data.poc_email.strip() if update_data.poc_email.strip() else None

    if update_data.owner_id is not None:
        if update_data.owner_id == 0:
            # Unassign
            asset.owner_id = None
            asset.owner_username = None
        else:
            owner_user = await db.get(User, update_data.owner_id)
            if not owner_user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Owner user with ID {update_data.owner_id} not found",
                )
            if owner_user.role != "owner":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"User '{owner_user.username}' has role '{owner_user.role}'. Only users with role 'owner' can be assigned as host owners.",
                )
            asset.owner_id = owner_user.id
            asset.owner_username = owner_user.username
    elif update_data.owner_id == 0:
        asset.owner_id = None
        asset.owner_username = None

    # Audit log entry for owner assignment
    await AuditService.log_event(
        db=db,
        action="ASSIGN_OWNER",
        target_type="Asset",
        target_id=str(asset.id),
        target_name=f"{asset.server_name or asset.ip_address} ({asset.ip_address})",
        actor=admin_or_analyst,
        request=request,
        details={
            "old_owner": old_owner,
            "new_owner": asset.owner_username,
            "old_server_name": old_server_name,
            "new_server_name": asset.server_name,
            "old_poc_name": old_poc_name,
            "new_poc_name": asset.poc_name,
            "old_poc_email": old_poc_email,
            "new_poc_email": asset.poc_email,
            "ip_address": asset.ip_address,
        },
    )

    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", response_model=AssetDeleteResponse)
async def delete_asset(
    asset_id: int,
    request: Request,
    delete_req: Optional[AssetDeleteRequest] = None,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found",
        )

    server_name = asset.server_name
    ip_address = asset.ip_address
    qualys_id = asset.qualys_id
    target_display = f"{server_name or ip_address} ({ip_address})"
    reason = (delete_req.reason.strip() if delete_req and delete_req.reason else "Decommissioned by administrator")

    # Snapshot asset data for the audit trail before deletion
    snapshot = {
        "id": asset.id,
        "qualys_id": qualys_id,
        "server_name": server_name,
        "ip_address": ip_address,
        "fqdn": asset.fqdn,
        "os_name": asset.os_name,
        "os_family": asset.os_family,
        "risk_score": asset.risk_score,
        "risk_level": asset.risk_level,
        "total_vulns": asset.total_vulns,
        "critical_vulns": asset.critical_vulns,
        "high_vulns": asset.high_vulns,
        "owner_username": asset.owner_username,
        "reason": reason,
    }

    # Clean up any references in MISP FS-ISAC assessment JSON reports
    misp_assessments = (await db.execute(select(MispCveAssessment))).scalars().all()
    for misp_item in misp_assessments:
        rep = misp_item.assessment_report or {}
        aff = rep.get("affected_assets", [])
        if any(a.get("asset_id") == asset_id for a in aff):
            filtered_aff = [a for a in aff if a.get("asset_id") != asset_id]
            rep["affected_assets"] = filtered_aff
            misp_item.assessment_report = rep
            misp_item.affected_assets_count = len(filtered_aff)
            if not filtered_aff and misp_item.match_type == "INVENTORY_PROACTIVE":
                misp_item.match_type = "NO_ASSETS_AFFECTED"

    # Record deletion in Audit Logs
    await AuditService.log_event(
        db=db,
        action="DELETE_ASSET",
        target_type="Asset",
        target_id=str(asset_id),
        target_name=target_display,
        actor=admin,
        request=request,
        details=snapshot,
    )

    # Delete the asset (cascades to detections, alerts, software)
    await db.delete(asset)
    await db.commit()

    return AssetDeleteResponse(
        success=True,
        message=f"Asset {target_display} has been permanently removed from the alert system.",
        deleted_asset_id=asset_id,
        server_name=server_name,
        ip_address=ip_address,
    )
