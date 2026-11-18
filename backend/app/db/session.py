"""Async database engine and strict TLS/SSL session lifecycle for Supabase PostgreSQL."""

from __future__ import annotations

from collections.abc import AsyncGenerator
import os
from pathlib import Path
import ssl
import tempfile
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None

_INSECURE_SSL_MODES = {"disable", "allow", "prefer", "no-verify", "false", "0"}
_CONFLICTING_SSL_PARAMS = {"sslmode", "ssl", "sslrootcert", "sslcert", "sslkey", "sslcrl"}


def _find_bundled_supabase_ca() -> Path | None:
    candidates = [
        Path(__file__).resolve().parents[2] / "certs" / "supabase-prod-ca-2021.crt",
        Path.cwd() / "backend" / "certs" / "supabase-prod-ca-2021.crt",
        Path.cwd() / "certs" / "supabase-prod-ca-2021.crt",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _find_optional_custom_ca_file(settings: Settings) -> Path | None:
    if settings.db_ssl_ca_file.strip():
        configured = Path(settings.db_ssl_ca_file.strip())
        if not configured.is_file():
            raise RuntimeError(
                f"Configured RG_DB_SSL_CA_FILE does not exist: {configured}"
            )
        return configured

    candidates: list[Path] = []
    if settings.persistent_data_dir.strip():
        candidates.append(Path(settings.persistent_data_dir.strip()) / ".rgstudio-db-ca.crt")
    candidates.append(Path.cwd() / ".rgstudio-db-ca.crt")
    candidates.append(Path(__file__).resolve().parents[3] / ".rgstudio-db-ca.crt")

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_postgres_ca_pems(settings: Settings) -> tuple[list[str], list[str]]:
    """Load verified Supabase Root 2021 CA and optional server-side custom CA PEMs."""
    pems: list[str] = []
    sources: list[str] = ["System/OpenSSL Trusted Roots"]

    supabase_ca = _find_bundled_supabase_ca()
    if supabase_ca is not None:
        text = supabase_ca.read_text(encoding="utf-8").strip()
        if "BEGIN CERTIFICATE" in text:
            pems.append(text)
            sources.append("Supabase Root 2021 CA (prod-ca-2021.crt)")

    custom_file = _find_optional_custom_ca_file(settings)
    if custom_file is not None:
        text = custom_file.read_text(encoding="utf-8").strip()
        if "BEGIN CERTIFICATE" not in text:
            raise RuntimeError(
                f"Custom PostgreSQL CA file does not contain a valid PEM certificate: {custom_file.name}"
            )
        pems.append(text)
        sources.append(f"Protected Server CA File ({custom_file.name})")

    inline_ca = settings.db_ssl_ca_cert.strip()
    if inline_ca:
        pem_text = inline_ca.replace("\\n", "\n")
        if "BEGIN CERTIFICATE" not in pem_text:
            raise RuntimeError(
                "RG_DB_SSL_CA_CERT does not contain a valid PEM certificate block."
            )
        pems.append(pem_text)
        sources.append("Hosting Secret CA (RG_DB_SSL_CA_CERT)")

    return pems, sources


def build_postgres_ssl_context(settings: Settings) -> ssl.SSLContext:
    """Create a strict TLS 1.2+ context with full certificate and hostname verification."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    extra_pems, _ = load_postgres_ca_pems(settings)
    for pem in extra_pems:
        ctx.load_verify_locations(cadata=pem)

    return ctx


def resolve_sync_ca_bundle_path(settings: Settings) -> Path | None:
    """Return a PEM CA bundle path containing system CAs + Supabase Root 2021 CA for psycopg."""
    extra_pems, _ = load_postgres_ca_pems(settings)
    if not extra_pems:
        default_ca = ssl.get_default_verify_paths().cafile
        return Path(default_ca) if default_ca and Path(default_ca).is_file() else None

    parts: list[str] = []
    default_ca = ssl.get_default_verify_paths().cafile
    if default_ca and Path(default_ca).is_file():
        parts.append(Path(default_ca).read_text(encoding="utf-8", errors="ignore"))
    parts.extend(extra_pems)
    combined = "\n".join(p.strip() for p in parts if p.strip()) + "\n"

    bundle_dir = (
        Path(settings.persistent_data_dir.strip())
        if settings.persistent_data_dir.strip()
        else Path(tempfile.gettempdir())
    )
    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = bundle_dir / ".rgstudio-combined-pg-ca.crt"
    fd = os.open(str(bundle_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(combined)
    return bundle_path


def sanitize_postgres_url(raw_url: str) -> str:
    """Remove conflicting SSL query params while rejecting explicit insecure sslmode settings."""
    parts = urlsplit(raw_url.strip())
    kept_params: list[tuple[str, str]] = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        lowered_k = k.lower()
        if lowered_k in _CONFLICTING_SSL_PARAMS:
            if lowered_k in {"sslmode", "ssl"} and v.strip().lower() in _INSECURE_SSL_MODES:
                raise ValueError(
                    f"Insecure PostgreSQL parameter '{k}={v}' is prohibited. Verified TLS (verify-full) is required."
                )
            continue
        kept_params.append((k, v))

    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(kept_params), parts.fragment)
    )


def get_tls_config_summary(settings: Settings) -> dict[str, Any]:
    """Return non-secret PostgreSQL TLS configuration summary for diagnostics."""
    supabase_ca = _find_bundled_supabase_ca()
    custom_ca = _find_optional_custom_ca_file(settings)
    _, sources = load_postgres_ca_pems(settings)
    return {
        "tls_enabled": True,
        "verify_full": True,
        "certificate_verification": "CERT_REQUIRED",
        "hostname_verification": True,
        "bundled_supabase_ca_loaded": supabase_ca is not None,
        "custom_ca_configured": bool(custom_ca or settings.db_ssl_ca_cert.strip()),
        "ca_sources": sources,
    }


def build_asyncpg_engine_config(settings: Settings) -> tuple[str, dict[str, Any]]:
    """Sanitize asyncpg URL and configure strict verified TLS + Supabase pooler compatibility."""
    if not settings.database_url:
        raise RuntimeError(
            "RG_DATABASE_URL is not configured. Set it in your server environment before connecting."
        )
    if not settings.db_ssl_require:
        raise RuntimeError(
            "RG_DB_SSL_REQUIRE=false is prohibited. Verified TLS is mandatory for Supabase PostgreSQL."
        )

    clean_url = sanitize_postgres_url(settings.database_url)
    connect_args: dict[str, Any] = {
        "ssl": build_postgres_ssl_context(settings),
    }
    if settings.db_pooler_mode:
        # Required when connecting through Supabase Supavisor / PgBouncer transaction pooler (port 6543)
        connect_args["statement_cache_size"] = 0

    return clean_url, connect_args


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        clean_url, connect_args = build_asyncpg_engine_config(settings)
        _engine = create_async_engine(
            clean_url,
            connect_args=connect_args,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            echo=False,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.close()
