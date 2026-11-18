"""Secure first-run Admin bootstrap endpoint (no hardcoded default passwords)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_client_meta
from app.core.config import get_settings
from app.core.rbac import PERMISSIONS, ROLE_PERMISSION_MAP, RoleCode
from app.core.security import constant_time_compare, hash_password
from app.db.session import get_db
from app.models.auth import Permission, Role, RolePermission, User
from app.models.operations import AuditLog
from app.schemas.auth import FirstRunAdminCreate, SetupStatusResponse, UserSummary

router = APIRouter(prefix="/setup", tags=["Setup"])


async def _ensure_roles_and_permissions(db: AsyncSession) -> dict[str, Role]:
    role_defs = [
        (RoleCode.ADMIN.value, "Administrator", "Full system administrator"),
        (RoleCode.MANAGER.value, "Manager", "Operational team and inventory manager"),
        (RoleCode.EMPLOYEE.value, "Employee", "Limited personal workspace access"),
    ]

    roles_by_code: dict[str, Role] = {}
    for code, name, desc in role_defs:
        existing = (
            await db.execute(select(Role).where(Role.code == code))
        ).scalar_one_or_none()
        if existing is None:
            existing = Role(code=code, name=name, description=desc, is_system=True)
            db.add(existing)
            await db.flush()
        roles_by_code[code] = existing

    perms_by_code: dict[str, Permission] = {}
    for code, module, desc in PERMISSIONS:
        perm = (
            await db.execute(select(Permission).where(Permission.code == code))
        ).scalar_one_or_none()
        if perm is None:
            perm = Permission(code=code, module=module, description=desc)
            db.add(perm)
            await db.flush()
        perms_by_code[code] = perm

    for role_code_enum, perm_codes in ROLE_PERMISSION_MAP.items():
        role_obj = roles_by_code[role_code_enum.value]
        for p_code in perm_codes:
            perm_obj = perms_by_code[p_code]
            existing_rp = (
                await db.execute(
                    select(RolePermission).where(
                        RolePermission.role_id == role_obj.id,
                        RolePermission.permission_id == perm_obj.id,
                    )
                )
            ).scalar_one_or_none()
            if existing_rp is None:
                db.add(RolePermission(role_id=role_obj.id, permission_id=perm_obj.id))

    await db.flush()
    return roles_by_code


@router.get("/status", response_model=SetupStatusResponse)
async def get_setup_status(db: AsyncSession = Depends(get_db)):
    admin_count = (
        await db.execute(
            select(func.count(User.id))
            .join(Role, User.role_id == Role.id)
            .where(Role.code == RoleCode.ADMIN.value, User.deleted_at.is_(None))
        )
    ).scalar_one()
    initialized = (admin_count or 0) > 0
    return SetupStatusResponse(
        initialized=initialized,
        requires_admin_setup=not initialized,
    )


@router.post(
    "/admin",
    response_model=UserSummary,
    status_code=status.HTTP_201_CREATED,
)
async def bootstrap_initial_admin(
    payload: FirstRunAdminCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()

    if settings.setup_bootstrap_token:
        if not payload.setup_token or not constant_time_compare(
            payload.setup_token, settings.setup_bootstrap_token
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid setup bootstrap token",
            )

    existing_admin_count = (
        await db.execute(
            select(func.count(User.id))
            .join(Role, User.role_id == Role.id)
            .where(Role.code == RoleCode.ADMIN.value, User.deleted_at.is_(None))
        )
    ).scalar_one()
    if (existing_admin_count or 0) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is already initialized; first-run admin setup is locked",
        )

    roles_by_code = await _ensure_roles_and_permissions(db)
    admin_role = roles_by_code[RoleCode.ADMIN.value]

    admin_user = User(
        full_name=payload.full_name.strip(),
        username=payload.username.strip().lower(),
        email=str(payload.email).strip().lower(),
        password_hash=hash_password(payload.password),
        role_id=admin_role.id,
        is_active=True,
    )
    db.add(admin_user)
    await db.flush()

    ip_address, user_agent = extract_client_meta(request)
    db.add(
        AuditLog(
            actor_user_id=admin_user.id,
            action="FIRST_RUN_ADMIN_CREATED",
            record_type="user",
            record_id=str(admin_user.id),
            metadata_json={"username": admin_user.username, "role": "admin"},
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )
    await db.commit()
    await db.refresh(admin_user)

    return UserSummary(
        id=admin_user.id,
        email=admin_user.email,
        username=admin_user.username,
        full_name=admin_user.full_name,
        role_code=admin_role.code,
        role_name=admin_role.name,
        is_active=admin_user.is_active,
        theme_preference=admin_user.theme_preference,
        permissions=ROLE_PERMISSION_MAP[RoleCode.ADMIN],
        last_login_at=admin_user.last_login_at,
        created_at=admin_user.created_at,
    )
