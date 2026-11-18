"""Automatic startup configuration validation and non-destructive state restore."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import get_session_factory


@dataclass
class FastApiStartupState:
    restored_at: str
    overall_status: str  # "Online" | "Offline" | "Configuration Required"
    supabase_configured: bool
    database_connected: bool
    jwt_configured: bool
    encryption_key_configured: bool
    persistent_storage_mode: str
    masked_db_host: str
    last_error: str | None = None


_startup_state: FastApiStartupState | None = None


def _mask_db_host(database_url: str) -> str:
    if not database_url:
        return ""
    try:
        parts = urlsplit(database_url)
        host = parts.hostname or ""
        port = parts.port or 6543
        if not host:
            return ""
        return f"{host[:6]}••••{host[-14:]}:{port}" if len(host) > 20 else f"{host}:{port}"
    except Exception:
        return ""


async def run_fastapi_startup_restore() -> FastApiStartupState:
    global _startup_state
    settings = get_settings()
    now = datetime.now(timezone.utc).isoformat()

    supabase_configured = bool(settings.database_url and settings.database_sync_url)
    jwt_configured = bool(
        settings.jwt_secret_key
        and settings.jwt_refresh_secret_key
        and not settings.jwt_secret_key.startswith("dev-only-")
        and not settings.jwt_refresh_secret_key.startswith("dev-only-")
    )
    encryption_key_configured = len(settings.config_encryption_key.strip()) >= 16

    storage_mode = "platform-env-vars"
    if settings.persistent_data_dir:
        try:
            Path(settings.persistent_data_dir).mkdir(parents=True, exist_ok=True)
            storage_mode = f"persistent-volume+env ({settings.persistent_data_dir})"
        except OSError:
            storage_mode = "platform-env-vars (persistent dir unwritable)"

    db_connected = False
    last_error: str | None = None

    if supabase_configured:
        try:
            factory = get_session_factory()
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            db_connected = True
        except Exception as exc:
            last_error = f"Database connectivity check failed: {type(exc).__name__}"

    if not supabase_configured or not jwt_configured:
        overall = "Configuration Required"
    elif db_connected:
        overall = "Online"
    else:
        overall = "Offline"

    _startup_state = FastApiStartupState(
        restored_at=now,
        overall_status=overall,
        supabase_configured=supabase_configured,
        database_connected=db_connected,
        jwt_configured=jwt_configured,
        encryption_key_configured=encryption_key_configured,
        persistent_storage_mode=storage_mode,
        masked_db_host=_mask_db_host(settings.database_url),
        last_error=last_error,
    )
    return _startup_state


REQUIRED_TABLES_20: tuple[str, ...] = (
    "roles",
    "permissions",
    "role_permissions",
    "users",
    "employees",
    "mobiles",
    "sim_cards",
    "gmail_accounts",
    "youtube_channels",
    "employee_teams",
    "team_members",
    "company_channels",
    "mobile_assignments",
    "sim_assignments",
    "gmail_assignments",
    "channel_assignments",
    "audit_logs",
    "app_settings",
    "backup_logs",
    "employee_requests",
)


async def verify_required_tables() -> dict[str, object]:
    """Read-only inspection of all 20 required RG Studio tables in public schema (never runs DDL)."""
    settings = get_settings()
    if not (settings.database_url and settings.database_sync_url):
        return {
            "tables_verified": False,
            "found_count": 0,
            "required_count": len(REQUIRED_TABLES_20),
            "found_tables": [],
            "missing_tables": list(REQUIRED_TABLES_20),
            "message": "Database URL is not configured on the backend.",
        }
    try:
        factory = get_session_factory()
        async with factory() as session:
            result = await session.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
                )
            )
            existing = {row[0] for row in result.fetchall()}
        found = [t for t in REQUIRED_TABLES_20 if t in existing]
        missing = [t for t in REQUIRED_TABLES_20 if t not in existing]
        ok = len(missing) == 0
        return {
            "tables_verified": ok,
            "found_count": len(found),
            "required_count": len(REQUIRED_TABLES_20),
            "found_tables": found,
            "missing_tables": missing,
            "message": (
                "All 20/20 required RG Studio tables verified."
                if ok
                else f"Found {len(found)}/20 tables. Missing: {', '.join(missing)}"
            ),
        }
    except Exception as exc:
        return {
            "tables_verified": False,
            "found_count": 0,
            "required_count": len(REQUIRED_TABLES_20),
            "found_tables": [],
            "missing_tables": list(REQUIRED_TABLES_20),
            "message": f"Table verification failed: {type(exc).__name__}",
        }


def get_startup_state() -> dict[str, object]:
    if _startup_state is None:
        settings = get_settings()
        return {
            "restored_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": "Configuration Required"
            if not (settings.database_url and settings.database_sync_url)
            else "Offline",
            "supabase_configured": bool(settings.database_url and settings.database_sync_url),
            "database_connected": False,
            "jwt_configured": bool(
                settings.jwt_secret_key and not settings.jwt_secret_key.startswith("dev-only-")
            ),
            "encryption_key_configured": len(settings.config_encryption_key.strip()) >= 16,
            "persistent_storage_mode": "platform-env-vars",
            "masked_db_host": _mask_db_host(settings.database_url),
            "last_error": None,
        }
    return asdict(_startup_state)
