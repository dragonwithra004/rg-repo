export interface SchemaTableSpec {
  index: number;
  name: string;
  domain: string;
  purpose: string;
  keyConstraints: string;
}

export interface ApiEndpointSpec {
  method: 'GET' | 'POST' | 'PATCH';
  path: string;
  access: string;
  purpose: string;
}

export const FOLDER_TREE_SPEC = `rg-studio-management-system/
├── backend/
│   ├── alembic/
│   │   ├── env.py
│   │   └── versions/
│   │       └── 0001_initial_schema.py
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── config.py          # Env-driven settings (zero secrets in code)
│   │   │   ├── rbac.py            # Canonical 3-role & 27-permission catalog
│   │   │   └── security.py        # Argon2id hashing + JWT lifecycle
│   │   ├── db/
│   │   │   ├── base.py            # UUID, Timestamp, SoftDelete mixins
│   │   │   └── session.py         # Async SQLAlchemy connection pool
│   │   ├── models/
│   │   │   ├── auth.py            # roles, permissions, role_permissions, users
│   │   │   └── operations.py      # Remaining 16 normalized domain & audit tables
│   │   ├── schemas/
│   │   │   └── auth.py            # Pydantic v2 validation & password rules
│   │   └── api/
│   │       ├── deps.py            # JWT bearer + require_roles / require_permission
│   │       └── v1/
│   │           ├── health.py      # Live SELECT 1 DB health check
│   │           ├── setup.py       # First-run Admin bootstrap (locked after init)
│   │           ├── auth.py        # Login, lockout, refresh, logout, theme pref
│   │           └── users.py       # Admin-only user creation & status control
│   └── tests/
│       └── test_phase1_auth_rbac.py
├── desktop/
│   ├── main.py                    # PySide6 entrypoint
│   ├── build_windows.spec         # PyInstaller Windows 10 packaging spec
│   ├── requirements.txt
│   └── app/
│       ├── config.py              # QSettings client config (API URL & theme only)
│       ├── services/
│       │   └── api_client.py      # HTTPS client, Online/Offline/Sync & read cache
│       └── ui/
│           ├── themes.py          # Dark & Light QSS stylesheets
│           ├── first_run_dialog.py
│           ├── login_window.py
│           └── main_window.py     # Role-filtered desktop navigation shell
├── migrations/
│   └── 001_initial_schema.sql     # 20-table Supabase PostgreSQL DDL + RLS
├── docs/
│   └── PHASE_1_ARCHITECTURE.md
├── server.ts                      # AI Studio Phase 1 API sandbox + Vite bridge
└── src/                           # Phase 1 Web Workbench & Architecture Inspector`;

export const SCHEMA_TABLES: SchemaTableSpec[] = [
  { index: 1, name: 'roles', domain: 'Auth & RBAC', purpose: 'System roles (admin, manager, employee)', keyConstraints: 'UNIQUE(code)' },
  { index: 2, name: 'permissions', domain: 'Auth & RBAC', purpose: 'Granular capability codes per module', keyConstraints: 'UNIQUE(code)' },
  { index: 3, name: 'role_permissions', domain: 'Auth & RBAC', purpose: 'Many-to-many role-to-permission matrix', keyConstraints: 'UNIQUE(role_id, permission_id)' },
  { index: 4, name: 'users', domain: 'Auth & RBAC', purpose: 'Application accounts, Argon2id hashes, lockouts', keyConstraints: 'FK role_id -> roles.id, token_version' },
  { index: 5, name: 'employees', domain: 'HR & Staff', purpose: 'Staff profiles, address, joining date, status', keyConstraints: 'UNIQUE(employee_code), FK user_id' },
  { index: 6, name: 'mobiles', domain: 'Hardware', purpose: 'Company mobile phones, IMEI 1/2, condition', keyConstraints: 'Partial UNIQUE(imei_1), UNIQUE(imei_2)' },
  { index: 7, name: 'sim_cards', domain: 'Telecom', purpose: 'SIM cards (Jazz, Zong, Ufone, Telenor, etc.)', keyConstraints: 'UNIQUE(phone_number), FK assigned_mobile_id' },
  { index: 8, name: 'gmail_accounts', domain: 'Accounts', purpose: 'Gmail ownership metadata (no passwords/OTPs)', keyConstraints: 'UNIQUE(email_address), category CHECK' },
  { index: 9, name: 'youtube_channels', domain: 'Channels', purpose: 'Employee-managed channels linked to Gmail', keyConstraints: 'UNIQUE(youtube_channel_id), FK associated_gmail_id' },
  { index: 10, name: 'company_channels', domain: 'My Running Channels', purpose: 'Company-operated channels separate from employee list', keyConstraints: 'UNIQUE(youtube_channel_id), status CHECK' },
  { index: 11, name: 'mobile_assignments', domain: 'Assignments', purpose: 'Immutable mobile assignment & return ledger', keyConstraints: 'Partial UNIQUE(mobile_id) WHERE status=active' },
  { index: 12, name: 'sim_assignments', domain: 'Assignments', purpose: 'Immutable SIM assignment & return ledger', keyConstraints: 'Partial UNIQUE(sim_id) WHERE status=active' },
  { index: 13, name: 'gmail_assignments', domain: 'Assignments', purpose: 'Immutable Gmail ownership assignment ledger', keyConstraints: 'Partial UNIQUE(gmail_id) WHERE status=active' },
  { index: 14, name: 'channel_assignments', domain: 'Assignments', purpose: 'Immutable YouTube channel assignment ledger', keyConstraints: 'Partial UNIQUE(channel_id) WHERE status=active' },
  { index: 15, name: 'employee_teams', domain: 'Teams', purpose: 'Operational teams for company channels', keyConstraints: 'UNIQUE(name)' },
  { index: 16, name: 'team_members', domain: 'Teams', purpose: 'Team membership join table', keyConstraints: 'UNIQUE(team_id, employee_id)' },
  { index: 17, name: 'audit_logs', domain: 'Security', purpose: 'Append-only security & activity trail', keyConstraints: 'Indexed created_at DESC, actor_user_id' },
  { index: 18, name: 'app_settings', domain: 'System', purpose: 'Global Admin-controlled key/value JSON config', keyConstraints: 'UNIQUE(key)' },
  { index: 19, name: 'backup_logs', domain: 'Backups', purpose: 'SHA-256 verified backup & restore records', keyConstraints: 'status CHECK (pending/verified/failed/restored)' },
  { index: 20, name: 'employee_requests', domain: 'Self-Service', purpose: 'Damage reports, return requests, profile edits', keyConstraints: 'FK employee_id -> employees.id' },
];

export const PHASE1_ENDPOINTS: ApiEndpointSpec[] = [
  { method: 'GET', path: '/api/v1/health', access: 'Public', purpose: 'Verifies API + live PostgreSQL SELECT 1 connectivity' },
  { method: 'GET', path: '/api/v1/setup/status', access: 'Public', purpose: 'Checks whether initial Administrator setup is required' },
  { method: 'POST', path: '/api/v1/setup/admin', access: 'First-Run Only', purpose: 'Bootstraps initial Admin + seeds roles/permissions; locks once initialized' },
  { method: 'POST', path: '/api/v1/auth/login', access: 'Public', purpose: 'Verifies Argon2id hash, enforces 5-attempt lockout, issues JWTs' },
  { method: 'POST', path: '/api/v1/auth/refresh', access: 'Refresh Token', purpose: 'Rotates access/refresh JWT pair if token_version matches' },
  { method: 'POST', path: '/api/v1/auth/logout', access: 'Authenticated', purpose: 'Increments token_version to revoke session & logs audit event' },
  { method: 'GET', path: '/api/v1/auth/me', access: 'Authenticated', purpose: 'Returns current user profile, role, and granted permissions' },
  { method: 'PATCH', path: '/api/v1/auth/me/theme', access: 'Authenticated', purpose: 'Persists dark/light theme preference' },
  { method: 'GET', path: '/api/v1/roles', access: 'Authenticated', purpose: 'Lists canonical roles and permission codes' },
  { method: 'GET', path: '/api/v1/users', access: 'Admin Only (403 otherwise)', purpose: 'Lists application user accounts' },
  { method: 'POST', path: '/api/v1/users', access: 'Admin Only (403 otherwise)', purpose: 'Creates Manager or Employee user account' },
  { method: 'PATCH', path: '/api/v1/users/{id}/status', access: 'Admin Only (403 otherwise)', purpose: 'Activates or deactivates user and revokes active tokens' },
];
