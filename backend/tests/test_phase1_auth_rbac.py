"""Phase 1 automated tests: security hashing, JWT lifecycle, RBAC, drivers, and SSL config."""

import ssl
from unittest.mock import MagicMock

from pydantic import ValidationError
import pytest

from app.core.config import Settings
from app.core.rbac import ROLE_PERMISSION_MAP, RoleCode
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.db.session import build_asyncpg_engine_config


def test_argon2id_hash_and_verify():
    raw = "StrongStudioPass#2026"
    hashed = hash_password(raw)
    assert hashed.startswith("$argon2id$")
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword123", hashed) is False


def test_jwt_access_token_roundtrip():
    token = create_access_token(
        subject="00000000-0000-0000-0000-000000000001",
        role="admin",
        token_version=1,
        session_id="sess-1",
    )
    payload = decode_access_token(token)
    assert payload["sub"] == "00000000-0000-0000-0000-000000000001"
    assert payload["role"] == "admin"
    assert payload["tv"] == 1
    assert payload["type"] == "access"


def test_database_driver_validation():
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql://user:pass@localhost:5432/db")

    with pytest.raises(ValidationError):
        Settings(database_sync_url="postgresql+asyncpg://user:pass@localhost:5432/db")

    valid = Settings(
        database_url="postgresql+asyncpg://user:pass@db-host:6543/postgres",
        database_sync_url="postgresql+psycopg://user:pass@db-host:5432/postgres?sslmode=require",
    )
    assert valid.database_url.startswith("postgresql+asyncpg://")
    assert valid.database_sync_url.startswith("postgresql+psycopg://")


def test_supabase_asyncpg_ssl_and_pooler_config():
    cfg = Settings(
        database_url="postgresql+asyncpg://user:pass@pooler-host:6543/postgres?sslmode=require",
        db_ssl_require=True,
        db_pooler_mode=True,
    )
    clean_url, connect_args = build_asyncpg_engine_config(cfg)
    assert "sslmode=" not in clean_url
    ctx = connect_args.get("ssl")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert connect_args.get("statement_cache_size") == 0


def test_rejects_insecure_sslmode_and_disabled_ssl():
    with pytest.raises(ValueError):
        build_asyncpg_engine_config(
            Settings(
                database_url="postgresql+asyncpg://user:pass@pooler-host:6543/postgres?sslmode=disable",
                db_ssl_require=True,
            )
        )

    with pytest.raises(RuntimeError):
        build_asyncpg_engine_config(
            Settings(
                database_url="postgresql+asyncpg://user:pass@pooler-host:6543/postgres",
                db_ssl_require=False,
            )
        )


def test_production_rejects_missing_db_or_unsafe_jwt():
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_rbac_role_boundaries():
    admin_perms = set(ROLE_PERMISSION_MAP[RoleCode.ADMIN])
    manager_perms = set(ROLE_PERMISSION_MAP[RoleCode.MANAGER])
    employee_perms = set(ROLE_PERMISSION_MAP[RoleCode.EMPLOYEE])

    assert "users.manage" in admin_perms
    assert "backups.manage" in admin_perms
    assert "settings.manage" in admin_perms

    # Manager restrictions
    assert "users.manage" not in manager_perms
    assert "settings.manage" not in manager_perms
    assert "backups.manage" not in manager_perms
    assert "audit.read" not in manager_perms

    # Employee restrictions
    assert "employees.read" not in employee_perms
    assert "mobiles.read" not in employee_perms
    assert "reports.read" not in employee_perms
    assert "self.read" in employee_perms
    assert "self.request" in employee_perms


@pytest.mark.asyncio
async def test_require_roles_rejects_unauthorized_role():
    from fastapi import HTTPException
    from app.api.deps import CurrentActor, require_roles

    guard = require_roles(RoleCode.ADMIN.value)
    manager_actor = CurrentActor(
        user=MagicMock(),
        role_code=RoleCode.MANAGER.value,
        role_name="Manager",
        permissions=set(ROLE_PERMISSION_MAP[RoleCode.MANAGER]),
    )
    with pytest.raises(HTTPException) as exc_info:
        await guard(manager_actor)
    assert exc_info.value.status_code == 403
