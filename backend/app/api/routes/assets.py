from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer
from app.models.user import User
from app.models.asset import Asset
from app.models.detection import Detection
from app.schemas.asset import AssetListItem, AssetDetail

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=List[AssetListItem])
async def list_assets(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (Critical, High, Medium, Low)"),
    is_risky: Optional[bool] = Query(None, description="Filter flagged risky assets"),
    tag: Optional[str] = Query(None, description="Filter by asset tag"),
    os_family: Optional[str] = Query(None, description="Filter by OS family"),
    search: Optional[str] = Query(None, description="Search by IP, FQDN, or OS"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    query = select(Asset)

    if risk_level:
        query = query.where(Asset.risk_level == risk_level)
    if is_risky is not None:
        query = query.where(Asset.is_risky == is_risky)
    if os_family:
        query = query.where(Asset.os_family == os_family)
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                Asset.ip_address.ilike(search_filter),
                Asset.fqdn.ilike(search_filter),
                Asset.os_name.ilike(search_filter),
                Asset.netbios_name.ilike(search_filter),
            )
        )

    # Order by risk score descending by default
    query = query.order_by(Asset.risk_score.desc(), Asset.id.asc()).offset(skip).limit(limit)

    res = await db.execute(query)
    assets = res.scalars().all()

    # In-memory tag filter if requested (since tags are stored as JSON list)
    if tag:
        tag_lower = tag.lower()
        assets = [a for a in assets if any(tag_lower in t.lower() for t in (a.tags or []))]

    return assets


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

    return asset
