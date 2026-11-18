"""Async database engine and session lifecycle for Supabase PostgreSQL."""

from collections.abc import AsyncGenerator
import ssl
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


def build_asyncpg_engine_config(settings: Settings) -> tuple[str, dict[str, Any]]:
    """Sanitize asyncpg URL and configure TLS SSL + Supabase pooler compatibility."""
    if not settings.database_url:
        raise RuntimeError(
            "RG_DATABASE_URL is not configured. Set it in your server environment before connecting."
        )

    parts = urlsplit(settings.database_url)
    # asyncpg rejects libpq's 'sslmode' query param; handle SSL explicitly via connect_args
    filtered_query = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in {"sslmode", "ssl"}
    ]
    clean_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(filtered_query), parts.fragment)
    )

    connect_args: dict[str, Any] = {}
    if settings.db_ssl_require:
        connect_args["ssl"] = ssl.create_default_context()
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
