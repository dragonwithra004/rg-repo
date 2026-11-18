"""Automatic startup configuration validation and non-destructive state restore."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import ssl
from urllib.parse import urlsplit

from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import get_session_factory, get_tls_config_summary


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
    tls_diagnostics: dict[str, object] = field(default_factory=dict)


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


def _classify_db_tls_exception(exc: Exception, base_summary: dict[str, object]) -> tuple[str, dict[str, object]]:
    diag = dict(base_summary)
    if isinstance(exc, ssl.SSLCertVerificationError) or "certificate" in str(exc).lower():
        msg = str(exc)
        is_hostname = "hostname" in msg.lower() or "ip address" in msg.lower()
        diag["certificate_valid"] = False
        diag["certificate_status"] = "verified" if is_hostname else "untrusted_ca"
        diag["hostname_valid"] = not is_hostname
        diag["hostname_status"] = "mismatch" if is_hostname else "not_verified"
        diag["connection_status"] = "tls_error"
        diag["missing_cert_guidance"] = (
            "Verify the server hostname matches your Supabase certificate SAN."
            if is_hostname
            else "Certificate chain could not be verified. Ensure Supabase Root 2021 CA (backend/certs/supabase-prod-ca-2021.crt) or RG_DB_SSL_CA_CERT / RG_DB_SSL_CA_FILE is present."
        )
        return f"PostgreSQL TLS verification failed: {diag['missing_cert_guidance']}", diag

    diag["certificate_valid"] = False
    diag["certificate_status"] = "error"
    diag["hostname_valid"] = False
    diag["hostname_status"] = "error"
    diag["connection_status"] = "network_error"
    diag["missing_cert_guidance"] = None
    return f"Database connectivity check failed: {type(exc).__name__}", diag


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
    tls_diag: dict[str, object] = get_tls_config_summary(settings)

    if supabase_configured:
        try:
            factory = get_session_factory()
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            db_connected = True
            tls_diag.update(
                {
                    "certificate_valid": True,
                    "certificate_status": "verified",
                    "hostname_valid": True,
                    "hostname_status": "verified",
                    "connection_status": "connected",
                    "missing_cert_guidance": None,
                }
            )
        except Exception as exc:
            last_error, tls_diag = _classify_db_tls_exception(exc, tls_diag)
    else:
        tls_diag.update(
            {
                "certificate_valid": False,
                "certificate_status": "not_checked",
                "hostname_valid": False,
                "hostname_status": "not_checked",
                "connection_status": "not_configured",
                "missing_cert_guidance": None,
            }
        )

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
        tls_diagnostics=tls_diag,
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
    tls_diag: dict[str, object] = get_tls_config_summary(settings)
    if not (settings.database_url and settings.database_sync_url):
        return {
            "tables_verified": False,
            "found_count": 0,
            "required_count": len(REQUIRED_TABLES_20),
            "found_tables": [],
            "missing_tables": list(REQUIRED_TABLES_20),
            "message": "Database URL is not configured on the backend.",
            "tls_diagnostics": {
                **tls_diag,
                "certificate_valid": False,
                "hostname_valid": False,
                "connection_status": "not_configured",
            },
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
            "tls_diagnostics": {
                **tls_diag,
                "certificate_valid": True,
                "certificate_status": "verified",
                "hostname_valid": True,
                "hostname_status": "verified",
                "connection_status": "connected",
            },
        }
    except Exception as exc:
        err_msg, err_diag = _classify_db_tls_exception(exc, tls_diag)
        return {
            "tables_verified": False,
            "found_count": 0,
            "required_count": len(REQUIRED_TABLES_20),
            "found_tables": [],
            "missing_tables": list(REQUIRED_TABLES_20),
            "message": err_msg,
            "tls_diagnostics": err_diag,
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
            "tls_diagnostics": get_tls_config_summary(settings),
        }
    return asdict(_startup_state)
