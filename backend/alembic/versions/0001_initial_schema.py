"""Initial 20-table schema foundation for RG Studio Management System.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-17
"""

from pathlib import Path
from alembic import op

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def _resolve_sql_path() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "migrations" / "001_initial_schema.sql",
        here.parents[2] / "migrations" / "001_initial_schema.sql",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Unable to locate migrations/001_initial_schema.sql in expected paths."
    )


def upgrade() -> None:
    sql_path = _resolve_sql_path()
    op.execute(sql_path.read_text(encoding="utf-8"))


def downgrade() -> None:
    tables = [
        "employee_requests",
        "backup_logs",
        "app_settings",
        "audit_logs",
        "channel_assignments",
        "gmail_assignments",
        "sim_assignments",
        "mobile_assignments",
        "company_channels",
        "team_members",
        "employee_teams",
        "youtube_channels",
        "gmail_accounts",
        "sim_cards",
        "mobiles",
        "employees",
        "users",
        "role_permissions",
        "permissions",
        "roles",
    ]
    for tbl in tables:
        op.execute(f"DROP TABLE IF EXISTS {tbl} CASCADE;")
    op.execute("DROP FUNCTION IF EXISTS rg_set_updated_at() CASCADE;")
