-- ============================================================================
-- RG STUDIO MANAGEMENT SYSTEM — PHASE 1 POSTGRESQL / SUPABASE MIGRATION (001)
-- Normalized 20-table relational schema + constraints + indexes + RLS baseline
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Automatic updated_at trigger function
CREATE OR REPLACE FUNCTION rg_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 1. roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(64) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. permissions
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(64) NOT NULL UNIQUE,
    module VARCHAR(64) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. role_permissions
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_role_permission UNIQUE (role_id, permission_id)
);

-- 4. users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(64) NOT NULL UNIQUE,
    full_name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    token_version INTEGER NOT NULL DEFAULT 1,
    theme_preference VARCHAR(16) NOT NULL DEFAULT 'dark' CHECK (theme_preference IN ('dark', 'light')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 5. employees
CREATE TABLE IF NOT EXISTS employees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_code VARCHAR(32) NOT NULL UNIQUE,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE SET NULL,
    full_name VARCHAR(120) NOT NULL,
    father_name VARCHAR(120) NOT NULL,
    phone_number VARCHAR(32) NOT NULL,
    residential_address TEXT NOT NULL,
    email VARCHAR(255),
    joining_date DATE NOT NULL,
    employment_status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (employment_status IN ('active', 'on_leave', 'inactive', 'terminated')),
    profile_photo_url VARCHAR(512),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_employees_full_name ON employees(full_name);
CREATE INDEX IF NOT EXISTS ix_employees_status ON employees(employment_status);

-- 6. mobiles
CREATE TABLE IF NOT EXISTS mobiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mobile_code VARCHAR(32) NOT NULL UNIQUE,
    brand VARCHAR(64) NOT NULL,
    model VARCHAR(96) NOT NULL,
    imei_1 VARCHAR(32),
    imei_2 VARCHAR(32),
    serial_number VARCHAR(64),
    purchase_date DATE,
    condition VARCHAR(32) NOT NULL DEFAULT 'good',
    current_status VARCHAR(24) NOT NULL DEFAULT 'available'
        CHECK (current_status IN ('available', 'assigned', 'under_repair', 'damaged', 'retired')),
    assigned_employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mobiles_imei_1_not_null
    ON mobiles(imei_1) WHERE imei_1 IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mobiles_imei_2_not_null
    ON mobiles(imei_2) WHERE imei_2 IS NOT NULL AND deleted_at IS NULL;

-- 7. sim_cards
CREATE TABLE IF NOT EXISTS sim_cards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sim_code VARCHAR(32) NOT NULL UNIQUE,
    phone_number VARCHAR(32) NOT NULL UNIQUE,
    network_provider VARCHAR(32) NOT NULL,
    sim_owner VARCHAR(120) NOT NULL,
    assigned_mobile_id UUID REFERENCES mobiles(id) ON DELETE SET NULL,
    assigned_employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'assigned', 'suspended', 'retired')),
    activation_date DATE,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 8. gmail_accounts (metadata & ownership ONLY — never passwords, OTPs, or recovery codes)
CREATE TABLE IF NOT EXISTS gmail_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gmail_code VARCHAR(32) NOT NULL UNIQUE,
    email_address VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(80) NOT NULL,
    last_name VARCHAR(80) NOT NULL,
    account_category VARCHAR(32) NOT NULL
        CHECK (account_category IN ('employee_account', 'company_account', 'other_authorized')),
    assigned_employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
    associated_mobile_id UUID REFERENCES mobiles(id) ON DELETE SET NULL,
    account_status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('active', 'restricted', 'suspended', 'archived')),
    creation_date DATE,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 9. youtube_channels
CREATE TABLE IF NOT EXISTS youtube_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_code VARCHAR(32) NOT NULL UNIQUE,
    channel_name VARCHAR(160) NOT NULL,
    channel_handle VARCHAR(120),
    youtube_channel_id VARCHAR(64) NOT NULL UNIQUE,
    channel_url VARCHAR(512) NOT NULL,
    associated_gmail_id UUID NOT NULL REFERENCES gmail_accounts(id) ON DELETE RESTRICT,
    assigned_employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
    channel_category VARCHAR(64) NOT NULL,
    creation_date DATE,
    status VARCHAR(24) NOT NULL DEFAULT 'active',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 10. employee_teams
CREATE TABLE IF NOT EXISTS employee_teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(96) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. team_members
CREATE TABLE IF NOT EXISTS team_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES employee_teams(id) ON DELETE CASCADE,
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    team_role VARCHAR(48) NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_team_member UNIQUE (team_id, employee_id)
);

-- 12. company_channels (My Running Channels — separate from employee channels)
CREATE TABLE IF NOT EXISTS company_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_code VARCHAR(32) NOT NULL UNIQUE,
    channel_name VARCHAR(160) NOT NULL,
    channel_handle VARCHAR(120),
    channel_url VARCHAR(512) NOT NULL,
    youtube_channel_id VARCHAR(64) NOT NULL UNIQUE,
    associated_company_gmail_id UUID NOT NULL REFERENCES gmail_accounts(id) ON DELETE RESTRICT,
    assigned_employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
    assigned_team_id UUID REFERENCES employee_teams(id) ON DELETE SET NULL,
    content_category VARCHAR(64) NOT NULL,
    channel_creation_date DATE,
    channel_status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (channel_status IN ('active', 'inactive', 'under_development', 'suspended')),
    internal_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 13. mobile_assignments
CREATE TABLE IF NOT EXISTS mobile_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mobile_id UUID NOT NULL REFERENCES mobiles(id) ON DELETE RESTRICT,
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
    assigned_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    returned_at TIMESTAMPTZ,
    status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'returned', 'transferred')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_mobile_assignment
    ON mobile_assignments(mobile_id) WHERE status = 'active';

-- 14. sim_assignments
CREATE TABLE IF NOT EXISTS sim_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sim_id UUID NOT NULL REFERENCES sim_cards(id) ON DELETE RESTRICT,
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
    assigned_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    returned_at TIMESTAMPTZ,
    status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'returned', 'transferred')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_sim_assignment
    ON sim_assignments(sim_id) WHERE status = 'active';

-- 15. gmail_assignments
CREATE TABLE IF NOT EXISTS gmail_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gmail_id UUID NOT NULL REFERENCES gmail_accounts(id) ON DELETE RESTRICT,
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
    assigned_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    returned_at TIMESTAMPTZ,
    status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'returned', 'transferred')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_gmail_assignment
    ON gmail_assignments(gmail_id) WHERE status = 'active';

-- 16. channel_assignments
CREATE TABLE IF NOT EXISTS channel_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL REFERENCES youtube_channels(id) ON DELETE RESTRICT,
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
    assigned_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    returned_at TIMESTAMPTZ,
    status VARCHAR(24) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'returned', 'transferred')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_channel_assignment
    ON channel_assignments(channel_id) WHERE status = 'active';

-- 17. audit_logs (append-only operational trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    record_type VARCHAR(64) NOT NULL,
    record_id VARCHAR(64),
    metadata_json JSONB,
    ip_address VARCHAR(64),
    user_agent VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs(created_at DESC);

-- 18. app_settings
CREATE TABLE IF NOT EXISTS app_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(96) NOT NULL UNIQUE,
    value_json JSONB NOT NULL,
    updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 19. backup_logs
CREATE TABLE IF NOT EXISTS backup_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    initiated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    backup_type VARCHAR(32) NOT NULL,
    storage_location VARCHAR(512) NOT NULL,
    checksum_sha256 VARCHAR(64),
    size_bytes BIGINT,
    status VARCHAR(24) NOT NULL CHECK (status IN ('pending', 'verified', 'failed', 'restored')),
    verified_at TIMESTAMPTZ,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 20. employee_requests
CREATE TABLE IF NOT EXISTS employee_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    request_type VARCHAR(32) NOT NULL
        CHECK (request_type IN ('damage_report', 'return_request', 'profile_correction')),
    target_record_type VARCHAR(32),
    target_record_id UUID,
    description TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'resolved')),
    reviewed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMPTZ,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Attach updated_at triggers
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'roles', 'permissions', 'role_permissions', 'users', 'employees',
        'mobiles', 'sim_cards', 'gmail_accounts', 'youtube_channels',
        'employee_teams', 'team_members', 'company_channels',
        'mobile_assignments', 'sim_assignments', 'gmail_assignments',
        'channel_assignments', 'app_settings', 'backup_logs', 'employee_requests'
    ]
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS trg_%I_updated_at ON %I; CREATE TRIGGER trg_%I_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION rg_set_updated_at();',
            t, t, t, t
        );
    END LOOP;
END $$;

-- Seed canonical roles (idempotent)
INSERT INTO roles (code, name, description, is_system)
VALUES
    ('admin', 'Administrator', 'Full system administrator', TRUE),
    ('manager', 'Manager', 'Operational team and inventory manager', TRUE),
    ('employee', 'Employee', 'Limited personal workspace access', TRUE)
ON CONFLICT (code) DO NOTHING;

-- Enable Row-Level Security on all tables so direct Supabase PostgREST access is locked down by default
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'roles', 'permissions', 'role_permissions', 'users', 'employees',
        'mobiles', 'sim_cards', 'gmail_accounts', 'youtube_channels',
        'employee_teams', 'team_members', 'company_channels',
        'mobile_assignments', 'sim_assignments', 'gmail_assignments',
        'channel_assignments', 'audit_logs', 'app_settings',
        'backup_logs', 'employee_requests'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', tbl);
    END LOOP;
END $$;
