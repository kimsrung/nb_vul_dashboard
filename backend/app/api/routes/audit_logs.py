import math
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer
from app.models.user import User
from app.models.audit_log import AuditLog
from app.schemas.audit_log import PaginatedAuditLogsResponse

router = APIRouter(prefix="/audit-logs", tags=["Audit & History Logs"])


@router.get("", response_model=PaginatedAuditLogsResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(15, ge=1, le=100, description="Items per page"),
    action: Optional[str] = Query(None, description="Filter by action (e.g., DELETE_ASSET, RESOLVE_ALERT)"),
    target_type: Optional[str] = Query(None, description="Filter by target type (e.g., Asset, Alert)"),
    search: Optional[str] = Query(None, description="Search by target name, actor, or details"),
    sort_by: Optional[str] = Query("created_at", description="Sort column (created_at, action, target_name, actor_username, ip_address)"),
    sort_order: Optional[str] = Query("desc", description="Sort direction (asc, desc)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    base_query = select(AuditLog)

    if action:
        base_query = base_query.where(AuditLog.action == action)
    if target_type:
        base_query = base_query.where(AuditLog.target_type == target_type)

    if search:
        s_term = f"%{search.strip()}%"
        base_query = base_query.where(
            or_(
                AuditLog.target_name.ilike(s_term),
                AuditLog.actor_username.ilike(s_term),
                AuditLog.action.ilike(s_term),
                AuditLog.target_id.ilike(s_term),
                AuditLog.target_type.ilike(s_term),
            )
        )

    # Count total
    count_query = select(func.count()).select_from(base_query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    # Paginate and sort
    skip = (page - 1) * page_size
    order_col = AuditLog.created_at
    if sort_by == "action":
        order_col = AuditLog.action
    elif sort_by in ("target", "target_name"):
        order_col = AuditLog.target_name
    elif sort_by in ("actor", "actor_username"):
        order_col = AuditLog.actor_username
    elif sort_by == "ip_address":
        order_col = AuditLog.ip_address
    elif sort_by == "created_at":
        order_col = AuditLog.created_at

    order_expr = order_col.asc() if (sort_order or "").lower() == "asc" else order_col.desc()
    query = base_query.order_by(order_expr, AuditLog.id.desc()).offset(skip).limit(page_size)
    res = await db.execute(query)
    items = res.scalars().all()
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedAuditLogsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
