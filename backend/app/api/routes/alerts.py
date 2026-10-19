from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer, require_admin
from app.models.user import User
from app.models.alert import Alert
from app.schemas.alert import AlertItem

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=List[AlertItem])
async def list_alerts(
    is_resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
    severity: Optional[str] = Query(None, description="Filter by alert severity"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    query = select(Alert)
    if is_resolved is not None:
        query = query.where(Alert.is_resolved == is_resolved)
    if severity:
        query = query.where(Alert.severity == severity)

    query = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit)
    res = await db.execute(query)
    return res.scalars().all()


@router.post("/{alert_id}/resolve", response_model=AlertItem)
async def resolve_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
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
