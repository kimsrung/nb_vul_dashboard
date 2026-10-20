from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer, require_analyst_or_admin
from app.models.user import User
from app.models.asset import Asset
from app.models.software import AssetSoftware
from app.schemas.software import SoftwareItem, SoftwareCreate

router = APIRouter(prefix="/assets/{asset_id}/software", tags=["Asset Software Inventory"])


@router.get("", response_model=List[SoftwareItem])
async def list_asset_software(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """List software packages and applications installed on an asset."""
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Scoping: owner role cannot inspect other hosts
    if user.role == "owner" and asset.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    query = select(AssetSoftware).where(AssetSoftware.asset_id == asset_id).order_by(AssetSoftware.product_name)
    res = await db.execute(query)
    return res.scalars().all()


@router.post("", response_model=SoftwareItem)
async def add_asset_software(
    asset_id: int,
    item_in: SoftwareCreate,
    db: AsyncSession = Depends(get_db),
    admin_or_analyst: User = Depends(require_analyst_or_admin),
):
    """Add an installed software package to an asset inventory."""
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    new_item = AssetSoftware(
        asset_id=asset_id,
        product_name=item_in.product_name.strip(),
        vendor=item_in.vendor.strip() if item_in.vendor else None,
        version=item_in.version.strip(),
        package_name=item_in.package_name.strip() if item_in.package_name else None,
        install_path=item_in.install_path.strip() if item_in.install_path else None,
        port=item_in.port,
        cpe=item_in.cpe.strip() if item_in.cpe else None,
    )
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)
    return new_item


@router.delete("/{software_id}")
async def delete_asset_software(
    asset_id: int,
    software_id: int,
    db: AsyncSession = Depends(get_db),
    admin_or_analyst: User = Depends(require_analyst_or_admin),
):
    """Delete a software item from asset inventory."""
    item = await db.get(AssetSoftware, software_id)
    if not item or item.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Software item not found")

    await db.delete(item)
    await db.commit()
    return {"success": True, "message": "Software item removed"}
