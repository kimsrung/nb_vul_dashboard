import math
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer, require_analyst_or_admin
from app.models.user import User
from app.models.alert import Alert
from app.models.asset import Asset
from app.schemas.alert import AlertItem, PaginatedAlertsResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=PaginatedAlertsResponse)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    is_resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
    severity: Optional[str] = Query(None, description="Filter by alert severity"),
    search: Optional[str] = Query(None, description="Search by title, message, server name, or IP"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    base_query = select(Alert)
    joined_asset = False

    # Scoping for owner role
    if user.role == "owner":
        base_query = base_query.join(Asset, Asset.id == Alert.asset_id).where(Asset.owner_id == user.id)
        joined_asset = True

    if is_resolved is not None:
        base_query = base_query.where(Alert.is_resolved == is_resolved)
    if severity:
        base_query = base_query.where(Alert.severity == severity)

    if search:
        if not joined_asset:
            base_query = base_query.outerjoin(Asset, Asset.id == Alert.asset_id)
        s_term = f"%{search.strip()}%"
        base_query = base_query.where(
            or_(
                Alert.title.ilike(s_term),
                Alert.message.ilike(s_term),
                Asset.server_name.ilike(s_term),
                Asset.ip_address.ilike(s_term),
            )
        )

    # Count total matching alerts
    count_query = select(func.count()).select_from(base_query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    # Paginate results
    skip = (page - 1) * page_size
    query = base_query.order_by(Alert.created_at.desc()).offset(skip).limit(page_size)
    res = await db.execute(query)
    items = res.scalars().all()
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedAlertsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("/{alert_id}/resolve", response_model=AlertItem)
async def resolve_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    admin_or_analyst: User = Depends(require_analyst_or_admin),
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert
