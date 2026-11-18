"""FastAPI security dependencies enforcing JWT authentication and backend RBAC."""

from dataclasses import dataclass
import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.auth import Role, RolePermission, User

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentActor:
    user: User
    role_code: str
    role_name: str
    permissions: set[str]


async def get_current_actor(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> CurrentActor:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(str(payload["sub"]))
        token_version = int(payload["tv"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
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
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )
    if user.token_version != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
        )

    permissions = {
        rp.permission.code
        for rp in user.role.role_permissions
        if rp.permission is not None
    }
    return CurrentActor(
        user=user,
        role_code=user.role.code,
        role_name=user.role.name,
        permissions=permissions,
    )


def require_roles(*allowed_roles: str):
    async def _guard(actor: CurrentActor = Depends(get_current_actor)) -> CurrentActor:
        if actor.role_code not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role privileges for this operation",
            )
        return actor

    return _guard


def require_permission(permission_code: str):
    async def _guard(actor: CurrentActor = Depends(get_current_actor)) -> CurrentActor:
        if permission_code not in actor.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission_code}",
            )
        return actor

    return _guard


def extract_client_meta(request: Request) -> tuple[str | None, str | None]:
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return ip_address, user_agent[:255] if user_agent else None
