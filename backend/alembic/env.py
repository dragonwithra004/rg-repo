"""Alembic environment configured for RG Studio Management System."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.core.config import get_settings
from app.db.base import Base
import app.models  # noqa: F401  Ensure all 20 models register on Base.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
target_metadata = Base.metadata


def _get_sync_url_and_args() -> tuple[str, dict]:
    if not settings.database_sync_url:
        raise RuntimeError(
            "RG_DATABASE_SYNC_URL is not configured. Set postgresql+psycopg://... before running Alembic."
        )
    connect_args = {}
    if settings.db_ssl_require and "sslmode=" not in settings.database_sync_url:
        connect_args["sslmode"] = "require"
    return settings.database_sync_url, connect_args


def run_migrations_offline() -> None:
    url, _ = _get_sync_url_and_args()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url, connect_args = _get_sync_url_and_args()
    connectable = create_engine(
        url,
        connect_args=connect_args,
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
