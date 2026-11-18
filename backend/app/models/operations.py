"""Normalized domain, assignment, audit, and system tables (20-table PostgreSQL schema)."""

from datetime import date, datetime
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Employee(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "employees"
    __table_args__ = (
        CheckConstraint(
            "employment_status IN ('active', 'on_leave', 'inactive', 'terminated')",
            name="ck_employees_status",
        ),
    )

    employee_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), unique=True, nullable=True
    )
    full_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    father_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    residential_address: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    joining_date: Mapped[date] = mapped_column(Date, nullable=False)
    employment_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="active", index=True
    )
    profile_photo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class Mobile(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "mobiles"
    __table_args__ = (
        CheckConstraint(
            "current_status IN ('available', 'assigned', 'under_repair', 'damaged', 'retired')",
            name="ck_mobiles_status",
        ),
        Index(
            "uq_mobiles_imei_1_not_null",
            "imei_1",
            unique=True,
            postgresql_where=text("imei_1 IS NOT NULL AND deleted_at IS NULL"),
        ),
        Index(
            "uq_mobiles_imei_2_not_null",
            "imei_2",
            unique=True,
            postgresql_where=text("imei_2 IS NOT NULL AND deleted_at IS NULL"),
        ),
    )

    mobile_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    brand: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    imei_1: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    imei_2: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    serial_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    purchase_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    condition: Mapped[str] = mapped_column(String(32), nullable=False, default="good")
    current_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="available", index=True
    )
    assigned_employee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class SimCard(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "sim_cards"
    __table_args__ = (
        CheckConstraint(
            "status IN ('available', 'assigned', 'suspended', 'retired')",
            name="ck_sim_cards_status",
        ),
    )

    sim_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    phone_number: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    network_provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sim_owner: Mapped[str] = mapped_column(String(120), nullable=False)
    assigned_mobile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mobiles.id", ondelete="SET NULL"), nullable=True
    )
    assigned_employee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="available", index=True)
    activation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class GmailAccount(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """Stores Gmail inventory metadata ONLY. Never stores passwords, OTPs, or recovery codes."""

    __tablename__ = "gmail_accounts"
    __table_args__ = (
        CheckConstraint(
            "account_category IN ('employee_account', 'company_account', 'other_authorized')",
            name="ck_gmail_category",
        ),
        CheckConstraint(
            "account_status IN ('active', 'restricted', 'suspended', 'archived')",
            name="ck_gmail_status",
        ),
    )

    gmail_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    email_address: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    first_name: Mapped[str] = mapped_column(String(80), nullable=False)
    last_name: Mapped[str] = mapped_column(String(80), nullable=False)
    account_category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    assigned_employee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True
    )
    associated_mobile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mobiles.id", ondelete="SET NULL"), nullable=True
    )
    account_status: Mapped[str] = mapped_column(String(24), nullable=False, default="active")
    creation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class YoutubeChannel(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "youtube_channels"

    channel_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    channel_name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    channel_handle: Mapped[str | None] = mapped_column(String(120), nullable=True)
    youtube_channel_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    channel_url: Mapped[str] = mapped_column(String(512), nullable=False)
    associated_gmail_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("gmail_accounts.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_employee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True
    )
    channel_category: Mapped[str] = mapped_column(String(64), nullable=False)
    creation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class EmployeeTeam(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "employee_teams"

    name: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class TeamMember(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "team_members"
    __table_args__ = (
        UniqueConstraint("team_id", "employee_id", name="uq_team_member"),
    )

    team_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employee_teams.id", ondelete="CASCADE"), nullable=False
    )
    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="CASCADE"), nullable=False
    )
    team_role: Mapped[str] = mapped_column(String(48), nullable=False, default="member")


class CompanyChannel(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """Dedicated module for channels operated directly by RG Studio."""

    __tablename__ = "company_channels"
    __table_args__ = (
        CheckConstraint(
            "channel_status IN ('active', 'inactive', 'under_development', 'suspended')",
            name="ck_company_channel_status",
        ),
    )

    channel_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    channel_name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    channel_handle: Mapped[str | None] = mapped_column(String(120), nullable=True)
    channel_url: Mapped[str] = mapped_column(String(512), nullable=False)
    youtube_channel_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    associated_company_gmail_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("gmail_accounts.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_employee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True
    )
    assigned_team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employee_teams.id", ondelete="SET NULL"), nullable=True
    )
    content_category: Mapped[str] = mapped_column(String(64), nullable=False)
    channel_creation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    channel_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="active", index=True
    )
    internal_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class MobileAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "mobile_assignments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'returned', 'transferred')",
            name="ck_mobile_assignments_status",
        ),
        Index(
            "uq_active_mobile_assignment",
            "mobile_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    mobile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mobiles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assigned_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("NOW()")
    )
    returned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class SimAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "sim_assignments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'returned', 'transferred')",
            name="ck_sim_assignments_status",
        ),
        Index(
            "uq_active_sim_assignment",
            "sim_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    sim_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sim_cards.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assigned_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("NOW()")
    )
    returned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class GmailAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "gmail_assignments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'returned', 'transferred')",
            name="ck_gmail_assignments_status",
        ),
        Index(
            "uq_active_gmail_assignment",
            "gmail_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    gmail_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("gmail_accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assigned_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("NOW()")
    )
    returned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class ChannelAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "channel_assignments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'returned', 'transferred')",
            name="ck_channel_assignments_status",
        ),
        Index(
            "uq_active_channel_assignment",
            "channel_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    channel_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("youtube_channels.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assigned_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("NOW()")
    )
    returned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "audit_logs"

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("NOW()"), index=True
    )


class AppSetting(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    value_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class BackupLog(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "backup_logs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'verified', 'failed', 'restored')",
            name="ck_backup_logs_status",
        ),
    )

    initiated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    backup_type: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_location: Mapped[str] = mapped_column(String(512), nullable=False)
    checksum_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class EmployeeRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "employee_requests"
    __table_args__ = (
        CheckConstraint(
            "request_type IN ('damage_report', 'return_request', 'profile_correction')",
            name="ck_employee_requests_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'resolved')",
            name="ck_employee_requests_status",
        ),
    )

    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("employees.id", ondelete="CASCADE"), nullable=False, index=True
    )
    request_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_record_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_record_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
