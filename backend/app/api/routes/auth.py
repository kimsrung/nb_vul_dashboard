from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import verify_password, hash_password, create_access_token
from app.models.user import User
from app.models.asset import Asset
from app.schemas.auth import LoginRequest, Token, UserResponse, UserCreate, UserUpdate
from app.api.deps import get_current_user, require_admin, require_analyst_or_admin

router = APIRouter(prefix="/auth", tags=["Authentication & User Management"])


@router.post("/login", response_model=Token)
async def login(login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.username == login_data.username))
    user = res.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account",
        )

    token = create_access_token(subject=user.username, role=user.role)
    return Token(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/owners", response_model=List[UserResponse])
async def list_available_owners(
    db: AsyncSession = Depends(get_db),
    caller: User = Depends(require_analyst_or_admin),
):
    """List users that can be assigned as asset owners (analysts, owners, admins)."""
    res = await db.execute(select(User).where(User.is_active == True).order_by(User.username))
    users = res.scalars().all()
    return users


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    res = await db.execute(select(User).order_by(User.id))
    users = res.scalars().all()
    
    result = []
    for u in users:
        # Count assigned assets
        count_res = await db.execute(select(func.count(Asset.id)).where(Asset.owner_id == u.id))
        assigned_cnt = count_res.scalar() or 0
        u_dict = {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "assigned_assets_count": assigned_cnt,
        }
        result.append(UserResponse(**u_dict))
    return result


@router.post("/users", response_model=UserResponse)
async def create_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    valid_roles = ["admin", "analyst", "owner", "viewer"]
    if user_in.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}",
        )

    existing = await db.execute(
        select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hash_password(user_in.password),
        role=user_in.role,
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target_user = await db.get(User, user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    valid_roles = ["admin", "analyst", "owner", "viewer"]
    if user_update.role is not None:
        if user_update.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}",
            )
        target_user.role = user_update.role

    if user_update.email is not None:
        target_user.email = user_update.email
    if user_update.full_name is not None:
        target_user.full_name = user_update.full_name
    if user_update.is_active is not None:
        # Prevent disabling own admin account
        if target_user.id == admin.id and not user_update.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate your own admin account",
            )
        target_user.is_active = user_update.is_active
    if user_update.password is not None and user_update.password.strip():
        target_user.hashed_password = hash_password(user_update.password.strip())

    await db.commit()
    await db.refresh(target_user)
    return target_user


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own admin account",
        )

    target_user = await db.get(User, user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    await db.delete(target_user)
    await db.commit()
    return {"success": True, "message": f"User {target_user.username} deleted"}
