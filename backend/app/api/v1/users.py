"""Phase 1 Admin-only User and Role management endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    CurrentActor,
    extract_client_meta,
    get_current_actor,
    require_roles,
)
from app.core.rbac import RoleCode
from app.core.security import hash_password
from app.db.session import get_db
from app.models.auth import Role, RolePermission, User
from app.models.operations import AuditLog
from app.schemas.auth import RoleOut, UserCreate, UserStatusUpdate, UserSummary

router = APIRouter(tags=["Users & Roles"])


def _to_user_summary(user: User) -> UserSummary:
    permissions = [
        rp.permission.code
        for rp in user.role.role_permissions
        if rp.permission is not None
    ]
    return UserSummary(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role_code=user.role.code,
        role_name=user.role.name,
        is_active=user.is_active,
        theme_preference=user.theme_preference,
        permissions=sorted(permissions),
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


@router.get("/roles", response_model=list[RoleOut])
async def list_roles(
    _: CurrentActor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Role).options(
        selectinload(Role.role_permissions).selectinload(RolePermission.permission)
    )
    roles = (await db.execute(stmt)).scalars().all()
    return [
        RoleOut(
            id=r.id,
            code=r.code,
            name=r.name,
            description=r.description,
            permissions=sorted(
                rp.permission.code for rp in r.role_permissions if rp.permission
            ),
        )
        for r in roles
    ]


@router.get("/users", response_model=list[UserSummary])
async def list_users(
    _: CurrentActor = Depends(require_roles(RoleCode.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(User)
        .options(
            selectinload(User.role)
            .selectinload(Role.role_permissions)
            .selectinload(RolePermission.permission)
        )
        .where(User.deleted_at.is_(None))
        .order_by(User.created_at.desc())
    )
    users = (await db.execute(stmt)).scalars().all()
    return [_to_user_summary(u) for u in users]


@router.post("/users", response_model=UserSummary, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    actor: CurrentActor = Depends(require_roles(RoleCode.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    normalized_email = str(payload.email).strip().lower()
    normalized_username = payload.username.strip().lower()

    existing = (
        await db.execute(
            select(User).where(
                or_(User.email == normalized_email, User.username == normalized_username),
                User.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email or username already exists",
        )

    role_obj = (
        await db.execute(
            select(Role)
            .options(
                selectinload(Role.role_permissions).selectinload(
                    RolePermission.permission
                )
            )
            .where(Role.code == payload.role_code)
        )
    ).scalar_one_or_none()
    if role_obj is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target role does not exist",
        )

    new_user = User(
        full_name=payload.full_name.strip(),
        username=normalized_username,
        email=normalized_email,
        password_hash=hash_password(payload.password),
        role_id=role_obj.id,
        is_active=True,
    )
    db.add(new_user)
    await db.flush()

    ip_address, user_agent = extract_client_meta(request)
    db.add(
        AuditLog(
            actor_user_id=actor.user.id,
            action="USER_CREATED",
            record_type="user",
            record_id=str(new_user.id),
            metadata_json={"role": role_obj.code, "username": new_user.username},
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )
    await db.commit()

    stmt = (
        select(User)
        .options(
            selectinload(User.role)
            .selectinload(Role.role_permissions)
            .selectinload(RolePermission.permission)
        )
        .where(User.id == new_user.id)
    )
    refreshed = (await db.execute(stmt)).scalar_one()
    return _to_user_summary(refreshed)


@router.patch("/users/{user_id}/status", response_model=UserSummary)
async def update_user_status(
    user_id: uuid.UUID,
    payload: UserStatusUpdate,
    request: Request,
    actor: CurrentActor = Depends(require_roles(RoleCode.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    if user_id == actor.user.id and not payload.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own active account",
        )

    stmt = (
        select(User)
        .options(
            selectinload(User.role)
            .selectinload(Role.role_permissions)
            .selectinload(RolePermission.permission)
        )
        .where(User.id == user_id, User.deleted_at.is_(None))
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    target.is_active = payload.is_active
    if not payload.is_active:
        target.token_version += 1

    ip_address, user_agent = extract_client_meta(request)
    db.add(
        AuditLog(
            actor_user_id=actor.user.id,
            action="USER_STATUS_CHANGED",
            record_type="user",
            record_id=str(target.id),
            metadata_json={"is_active": payload.is_active},
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )
    await db.commit()
    return _to_user_summary(target)
