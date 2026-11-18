"""Authentication routes: login, refresh, logout, profile, and theme preference."""

from datetime import datetime, timedelta, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
import jwt
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import CurrentActor, extract_client_meta, get_current_actor
from app.core.config import get_settings
from app.core.rbac import RoleCode
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.db.session import get_db
from app.models.auth import Role, RolePermission, User
from app.models.operations import AuditLog
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    ThemeUpdateRequest,
    TokenResponse,
    UserSummary,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _build_user_summary(user: User, permissions: list[str]) -> UserSummary:
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


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register_employee_account(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Self-registration endpoint strictly restricted to the Employee role after setup."""
    settings = get_settings()
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
            detail="An account with this email or username already exists",
        )

    employee_role = (
        await db.execute(
            select(Role)
            .options(
                selectinload(Role.role_permissions).selectinload(
                    RolePermission.permission
                )
            )
            .where(Role.code == RoleCode.EMPLOYEE.value)
        )
    ).scalar_one_or_none()
    if employee_role is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is not initialized yet. Complete first-run Administrator setup first.",
        )

    now = datetime.now(timezone.utc)
    user = User(
        full_name=payload.full_name.strip(),
        username=normalized_username,
        email=normalized_email,
        password_hash=hash_password(payload.password),
        role_id=employee_role.id,
        is_active=True,
        last_login_at=now,
    )
    db.add(user)
    await db.flush()

    session_id = str(uuid.uuid4())
    ip_address, user_agent = extract_client_meta(request)
    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="USER_SELF_REGISTERED",
            record_type="user",
            record_id=str(user.id),
            metadata_json={"role": RoleCode.EMPLOYEE.value, "username": user.username},
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
        .where(User.id == user.id)
    )
    refreshed = (await db.execute(stmt)).scalar_one()
    permissions = [
        rp.permission.code
        for rp in refreshed.role.role_permissions
        if rp.permission is not None
    ]
    return TokenResponse(
        access_token=create_access_token(
            subject=str(refreshed.id),
            role=refreshed.role.code,
            token_version=refreshed.token_version,
            session_id=session_id,
        ),
        refresh_token=create_refresh_token(
            subject=str(refreshed.id),
            token_version=refreshed.token_version,
            session_id=session_id,
        ),
        expires_in_seconds=settings.access_token_expire_minutes * 60,
        user=_build_user_summary(refreshed, permissions),
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    identifier = payload.identifier.strip().lower()
    now = datetime.now(timezone.utc)
    ip_address, user_agent = extract_client_meta(request)

    stmt = (
        select(User)
        .options(
            selectinload(User.role)
            .selectinload(Role.role_permissions)
            .selectinload(RolePermission.permission)
        )
        .where(
            or_(User.email == identifier, User.username == identifier),
            User.deleted_at.is_(None),
        )
    )
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an Administrator.",
        )

    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to repeated failed sign-in attempts.",
        )

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.lockout_threshold:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
        db.add(
            AuditLog(
                actor_user_id=user.id,
                action="LOGIN_FAILED",
                record_type="user",
                record_id=str(user.id),
                metadata_json={"failed_attempts": user.failed_login_attempts},
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    session_id = str(uuid.uuid4())
    permissions = [
        rp.permission.code
        for rp in user.role.role_permissions
        if rp.permission is not None
    ]

    access_token = create_access_token(
        subject=str(user.id),
        role=user.role.code,
        token_version=user.token_version,
        session_id=session_id,
    )
    refresh_token = create_refresh_token(
        subject=str(user.id),
        token_version=user.token_version,
        session_id=session_id,
    )

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="LOGIN_SUCCESS",
            record_type="user",
            record_id=str(user.id),
            metadata_json={"session_id": session_id, "role": user.role.code},
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=settings.access_token_expire_minutes * 60,
        user=_build_user_summary(user, permissions),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_session(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    try:
        decoded = decode_refresh_token(payload.refresh_token)
        user_id = uuid.UUID(str(decoded["sub"]))
        token_version = int(decoded["tv"])
        session_id = str(decoded.get("sid") or uuid.uuid4())
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
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
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None or not user.is_active or user.token_version != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or account inactive",
        )

    permissions = [
        rp.permission.code
        for rp in user.role.role_permissions
        if rp.permission is not None
    ]
    return TokenResponse(
        access_token=create_access_token(
            subject=str(user.id),
            role=user.role.code,
            token_version=user.token_version,
            session_id=session_id,
        ),
        refresh_token=create_refresh_token(
            subject=str(user.id),
            token_version=user.token_version,
            session_id=session_id,
        ),
        expires_in_seconds=settings.access_token_expire_minutes * 60,
        user=_build_user_summary(user, permissions),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    actor: CurrentActor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
):
    actor.user.token_version += 1
    ip_address, user_agent = extract_client_meta(request)
    db.add(
        AuditLog(
            actor_user_id=actor.user.id,
            action="LOGOUT",
            record_type="user",
            record_id=str(actor.user.id),
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )
    await db.commit()


@router.get("/me", response_model=UserSummary)
async def get_me(actor: CurrentActor = Depends(get_current_actor)):
    return _build_user_summary(actor.user, list(actor.permissions))


@router.patch("/me/theme", response_model=UserSummary)
async def update_theme_preference(
    payload: ThemeUpdateRequest,
    actor: CurrentActor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
):
    actor.user.theme_preference = payload.theme_preference
    await db.commit()
    return _build_user_summary(actor.user, list(actor.permissions))
