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

    # Paginate
    skip = (page - 1) * page_size
    query = base_query.order_by(AuditLog.created_at.desc()).offset(skip).limit(page_size)
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
