import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import {
  DecryptedInfraConfig,
  parsePostgresConnectionUri,
  PermanentConfigStore,
  REQUIRED_TABLES_20,
} from './server/configStore';

dotenv.config();

type RoleCode = 'admin' | 'manager' | 'employee';

interface SandboxUser {
  id: string;
  full_name: string;
  username: string;
  email: string;
  password_hash: string;
  role_code: RoleCode;
  role_name: string;
  is_active: boolean;
  failed_login_attempts: number;
  locked_until: string | null;
  last_login_at: string | null;
  token_version: number;
  theme_preference: 'dark' | 'light';
  created_at: string;
}

interface SandboxAuditLog {
  id: string;
  actor_user_id: string | null;
  actor_username: string | null;
  action: string;
  record_type: string;
  record_id: string | null;
  details: string;
  created_at: string;
}

interface SandboxStore {
  users: SandboxUser[];
  audit_logs: SandboxAuditLog[];
}

const configStore = new PermanentConfigStore();

function resolveSandboxStorePath(): string {
  const persistentDir = String(process.env.RG_PERSISTENT_DATA_DIR || '').trim();
  if (persistentDir) {
    try {
      fs.mkdirSync(persistentDir, { recursive: true });
      return path.join(persistentDir, '.rgstudio-phase1-sandbox.json');
    } catch {
      // Fallback to workspace cwd
    }
  }
  return path.resolve(process.cwd(), '.rgstudio-phase1-sandbox.json');
}

const STORE_PATH = resolveSandboxStorePath();
let cachedSandboxJwtSecret: string | null = null;
function getSandboxJwtSecret(): string {
  if (!cachedSandboxJwtSecret) {
    cachedSandboxJwtSecret = configStore.getOrCreateSandboxJwtSecret();
  }
  return cachedSandboxJwtSecret;
}

const ROLE_NAMES: Record<RoleCode, string> = {
  admin: 'Administrator',
  manager: 'Manager',
  employee: 'Employee',
};

const ROLE_PERMISSIONS: Record<RoleCode, string[]> = {
  admin: [
    'dashboard.view',
    'employees.read',
    'employees.write',
    'employees.deactivate',
    'employees.read_restricted',
    'mobiles.read',
    'mobiles.write',
    'sims.read',
    'sims.write',
    'gmail.read',
    'gmail.write',
    'youtube.read',
    'youtube.write',
    'company_channels.read',
    'company_channels.write',
    'assignments.read',
    'assignments.write',
    'reports.read',
    'reports.export',
    'users.manage',
    'roles.manage',
    'audit.read',
    'settings.manage',
    'backups.manage',
  ],
  manager: [
    'dashboard.view',
    'employees.read',
    'employees.write',
    'mobiles.read',
    'mobiles.write',
    'sims.read',
    'sims.write',
    'gmail.read',
    'gmail.write',
    'youtube.read',
    'youtube.write',
    'company_channels.read',
    'assignments.read',
    'assignments.write',
    'reports.read',
    'reports.export',
  ],
  employee: ['dashboard.view_self', 'self.read', 'self.request'],
};

function readStore(): SandboxStore {
  if (!fs.existsSync(STORE_PATH)) {
    return { users: [], audit_logs: [] };
  }
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf-8');
    return JSON.parse(raw) as SandboxStore;
  } catch {
    return { users: [], audit_logs: [] };
  }
}

function writeStore(store: SandboxStore): void {
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, originalHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const original = Buffer.from(originalHex, 'hex');
  if (derived.length !== original.length) return false;
  return crypto.timingSafeEqual(derived, original);
}

function signToken(payload: Record<string, unknown>, ttlSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = Buffer.from(
    JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds })
  ).toString('base64url');
  const sig = crypto
    .createHmac('sha256', getSandboxJwtSecret())
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const expected = crypto
    .createHmac('sha256', getSandboxJwtSecret())
    .update(`${header}.${body}`)
    .digest('base64url');
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const decoded = JSON.parse(Buffer.from(body, 'base64url').toString('utf-8')) as Record<
      string,
      unknown
    >;
    if (typeof decoded.exp !== 'number' || decoded.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function toPublicUser(u: SandboxUser) {
  return {
    id: u.id,
    full_name: u.full_name,
    username: u.username,
    email: u.email,
    role_code: u.role_code,
    role_name: u.role_name,
    is_active: u.is_active,
    theme_preference: u.theme_preference,
    permissions: ROLE_PERMISSIONS[u.role_code],
    last_login_at: u.last_login_at,
    created_at: u.created_at,
  };
}

function validatePasswordStrength(password: string): string | null {
  if (typeof password !== 'string' || password.length < 12) {
    return 'Password must be at least 12 characters.';
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must include uppercase, lowercase, and numeric characters.';
  }
  return null;
}

interface AuthedRequest extends Request {
  actor?: SandboxUser;
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ detail: 'Authentication required.' });
  }
  const token = header.slice('Bearer '.length);
  const payload = verifyToken(token);
  if (!payload || payload.type !== 'access' || typeof payload.sub !== 'string') {
    return res.status(401).json({ detail: 'Invalid or expired session token.' });
  }
  const store = readStore();
  const user = store.users.find((u) => u.id === payload.sub);
  if (!user) {
    return res.status(401).json({ detail: 'Account not found.' });
  }
  if (!user.is_active) {
    return res.status(403).json({ detail: 'Account is deactivated.' });
  }
  if (user.token_version !== payload.tv) {
    return res.status(401).json({ detail: 'Session revoked.' });
  }
  req.actor = user;
  return next();
}

function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.actor || req.actor.role_code !== 'admin') {
    return res.status(403).json({
      detail: 'Forbidden: Administrator privileges are required for this endpoint.',
    });
  }
  return next();
}

async function startServer() {
  const app = express();
  app.use(express.json());

  app.get('/api/v1/health', (_req, res) => {
    const cfg = configStore.readConfig();
    const startup = configStore.getStartupRestoreState();
    res.json({
      status: 'online',
      service: 'phase1-sandbox-api',
      mode: 'sandbox',
      database: 'phase1-sandbox-store',
      fastapi_configured: Boolean(cfg.fastapi_base_url),
      fastapi_base_url: cfg.fastapi_base_url || '',
      fastapi_healthy: Boolean(cfg.last_backend_test_ok),
      overall_infra_status: startup.overall_status,
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/v1/setup/status', (_req, res) => {
    const store = readStore();
    const cfg = configStore.readConfig();
    const startup = configStore.getStartupRestoreState();
    const adminExists = store.users.some((u) => u.role_code === 'admin');
    res.json({
      initialized: adminExists,
      requires_admin_setup: !adminExists,
      service: 'phase1-sandbox-api',
      mode: 'sandbox',
      fastapi_configured: Boolean(cfg.fastapi_base_url),
      fastapi_base_url: cfg.fastapi_base_url || '',
      fastapi_healthy: Boolean(cfg.last_backend_test_ok),
      overall_infra_status: startup.overall_status,
    });
  });

  app.post('/api/v1/setup/admin', (req, res) => {
    const store = readStore();
    if (store.users.some((u) => u.role_code === 'admin')) {
      return res.status(409).json({
        detail: 'System is already initialized. First-run admin setup is locked.',
      });
    }

    const fullName = String(req.body?.full_name || '').trim();
    const username = String(req.body?.username || '').trim().toLowerCase();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (fullName.length < 2 || username.length < 3 || !email.includes('@')) {
      return res.status(400).json({
        detail: 'Valid full name, username (3+ chars), and email are required.',
      });
    }
    const pwError = validatePasswordStrength(password);
    if (pwError) {
      return res.status(400).json({ detail: pwError });
    }

    const now = new Date().toISOString();
    const adminUser: SandboxUser = {
      id: crypto.randomUUID(),
      full_name: fullName,
      username,
      email,
      password_hash: hashPassword(password),
      role_code: 'admin',
      role_name: ROLE_NAMES.admin,
      is_active: true,
      failed_login_attempts: 0,
      locked_until: null,
      last_login_at: null,
      token_version: 1,
      theme_preference: 'dark',
      created_at: now,
    };

    store.users.push(adminUser);
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: adminUser.id,
      actor_username: adminUser.username,
      action: 'FIRST_RUN_ADMIN_CREATED',
      record_type: 'user',
      record_id: adminUser.id,
      details: `Initial Administrator '${adminUser.username}' provisioned via first-run setup.`,
      created_at: now,
    });
    writeStore(store);

    return res.status(201).json(toPublicUser(adminUser));
  });

  app.post('/api/v1/auth/register', (req, res) => {
    const store = readStore();
    if (!store.users.some((u) => u.role_code === 'admin')) {
      return res.status(409).json({
        detail: 'System is not initialized yet. Create the initial Administrator account first.',
      });
    }

    const fullName = String(req.body?.full_name || '').trim();
    const username = String(req.body?.username || '').trim().toLowerCase();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (fullName.length < 2 || username.length < 3 || !email.includes('@')) {
      return res.status(400).json({
        detail: 'Valid full name, username (3+ chars), and email are required.',
      });
    }
    const pwError = validatePasswordStrength(password);
    if (pwError) {
      return res.status(400).json({ detail: pwError });
    }
    if (store.users.some((u) => u.email === email || u.username === username)) {
      return res.status(409).json({
        detail: 'An account with this email or username already exists.',
      });
    }

    const now = new Date().toISOString();
    const newUser: SandboxUser = {
      id: crypto.randomUUID(),
      full_name: fullName,
      username,
      email,
      password_hash: hashPassword(password),
      role_code: 'employee',
      role_name: ROLE_NAMES.employee,
      is_active: true,
      failed_login_attempts: 0,
      locked_until: null,
      last_login_at: now,
      token_version: 1,
      theme_preference: 'dark',
      created_at: now,
    };

    store.users.push(newUser);
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: newUser.id,
      actor_username: newUser.username,
      action: 'USER_SELF_REGISTERED',
      record_type: 'user',
      record_id: newUser.id,
      details: `Employee account '@${newUser.username}' created via Sign Up.`,
      created_at: now,
    });
    writeStore(store);

    const ttlSeconds = req.body?.remember_me === false ? 1800 : 604800;
    const accessToken = signToken(
      { sub: newUser.id, role: newUser.role_code, tv: newUser.token_version, type: 'access' },
      ttlSeconds
    );
    return res.status(201).json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in_seconds: ttlSeconds,
      user: toPublicUser(newUser),
    });
  });

  app.post('/api/v1/auth/login', (req, res) => {
    const identifier = String(req.body?.identifier || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!identifier || !password) {
      return res.status(400).json({ detail: 'Identifier and password are required.' });
    }

    const store = readStore();
    const user = store.users.find(
      (u) => u.email === identifier || u.username === identifier
    );

    if (!user) {
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }
    if (!user.is_active) {
      return res.status(403).json({
        detail: 'Account is deactivated. Contact an Administrator.',
      });
    }

    const nowMs = Date.now();
    if (user.locked_until && new Date(user.locked_until).getTime() > nowMs) {
      return res.status(423).json({
        detail: 'Account temporarily locked due to repeated failed sign-in attempts.',
      });
    }

    if (!verifyPassword(password, user.password_hash)) {
      user.failed_login_attempts += 1;
      if (user.failed_login_attempts >= 5) {
        user.locked_until = new Date(nowMs + 15 * 60 * 1000).toISOString();
      }
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: user.id,
        actor_username: user.username,
        action: 'LOGIN_FAILED',
        record_type: 'user',
        record_id: user.id,
        details: `Failed login attempt (${user.failed_login_attempts}/5).`,
        created_at: new Date(nowMs).toISOString(),
      });
      writeStore(store);
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    user.failed_login_attempts = 0;
    user.locked_until = null;
    user.last_login_at = new Date(nowMs).toISOString();

    const ttlSeconds = req.body?.remember_me === false ? 1800 : 604800;
    const accessToken = signToken(
      { sub: user.id, role: user.role_code, tv: user.token_version, type: 'access' },
      ttlSeconds
    );

    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: user.id,
      actor_username: user.username,
      action: 'LOGIN_SUCCESS',
      record_type: 'user',
      record_id: user.id,
      details: `Authenticated as ${user.role_name}.`,
      created_at: new Date(nowMs).toISOString(),
    });
    writeStore(store);

    return res.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in_seconds: ttlSeconds,
      user: toPublicUser(user),
    });
  });

  app.post('/api/v1/auth/logout', requireAuth, (req: AuthedRequest, res) => {
    const store = readStore();
    const user = store.users.find((u) => u.id === req.actor!.id);
    if (user) {
      user.token_version += 1;
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: user.id,
        actor_username: user.username,
        action: 'LOGOUT',
        record_type: 'user',
        record_id: user.id,
        details: 'Session ended and token version incremented.',
        created_at: new Date().toISOString(),
      });
      writeStore(store);
    }
    res.status(204).end();
  });

  app.get('/api/v1/auth/me', requireAuth, (req: AuthedRequest, res) => {
    res.json(toPublicUser(req.actor!));
  });

  app.patch('/api/v1/auth/me/theme', requireAuth, (req: AuthedRequest, res) => {
    const pref = req.body?.theme_preference;
    if (pref !== 'dark' && pref !== 'light') {
      return res.status(400).json({ detail: 'Theme must be dark or light.' });
    }
    const store = readStore();
    const user = store.users.find((u) => u.id === req.actor!.id);
    if (!user) {
      return res.status(404).json({ detail: 'User not found.' });
    }
    user.theme_preference = pref;
    writeStore(store);
    res.json(toPublicUser(user));
  });

  app.get('/api/v1/roles', requireAuth, (_req, res) => {
    res.json(
      (['admin', 'manager', 'employee'] as RoleCode[]).map((code) => ({
        code,
        name: ROLE_NAMES[code],
        permissions: ROLE_PERMISSIONS[code],
      }))
    );
  });

  app.get('/api/v1/users', requireAuth, requireAdmin, (_req, res) => {
    const store = readStore();
    res.json(store.users.map(toPublicUser));
  });

  app.post('/api/v1/users', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const fullName = String(req.body?.full_name || '').trim();
    const username = String(req.body?.username || '').trim().toLowerCase();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const roleCode = String(req.body?.role_code || '') as RoleCode;

    if (roleCode !== 'manager' && roleCode !== 'employee') {
      return res.status(400).json({
        detail: 'New accounts via User Management must have role manager or employee.',
      });
    }
    if (fullName.length < 2 || username.length < 3 || !email.includes('@')) {
      return res.status(400).json({
        detail: 'Valid full name, username, and email are required.',
      });
    }
    const pwError = validatePasswordStrength(password);
    if (pwError) {
      return res.status(400).json({ detail: pwError });
    }

    const store = readStore();
    if (store.users.some((u) => u.email === email || u.username === username)) {
      return res.status(409).json({
        detail: 'A user with this email or username already exists.',
      });
    }

    const now = new Date().toISOString();
    const created: SandboxUser = {
      id: crypto.randomUUID(),
      full_name: fullName,
      username,
      email,
      password_hash: hashPassword(password),
      role_code: roleCode,
      role_name: ROLE_NAMES[roleCode],
      is_active: true,
      failed_login_attempts: 0,
      locked_until: null,
      last_login_at: null,
      token_version: 1,
      theme_preference: 'dark',
      created_at: now,
    };
    store.users.push(created);
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'USER_CREATED',
      record_type: 'user',
      record_id: created.id,
      details: `Created ${created.role_name} account '@${created.username}'.`,
      created_at: now,
    });
    writeStore(store);

    return res.status(201).json(toPublicUser(created));
  });

  app.patch(
    '/api/v1/users/:id/status',
    requireAuth,
    requireAdmin,
    (req: AuthedRequest, res) => {
      const targetId = req.params.id;
      const isActive = Boolean(req.body?.is_active);
      if (targetId === req.actor!.id && !isActive) {
        return res.status(400).json({
          detail: 'Administrators cannot deactivate their own active account.',
        });
      }
      const store = readStore();
      const target = store.users.find((u) => u.id === targetId);
      if (!target) {
        return res.status(404).json({ detail: 'User not found.' });
      }
      target.is_active = isActive;
      if (!isActive) {
        target.token_version += 1;
      }
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'USER_STATUS_CHANGED',
        record_type: 'user',
        record_id: target.id,
        details: `Set '@${target.username}' active=${isActive}.`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);
      return res.json(toPublicUser(target));
    }
  );

  app.get('/api/v1/audit-logs', requireAuth, requireAdmin, (_req, res) => {
    const store = readStore();
    res.json(store.audit_logs.slice(0, 100));
  });

  // --- Admin-only Phase 1 Permanent Infrastructure & Secret Management Endpoints ---
  function buildMaskedStatus(cfg: DecryptedInfraConfig, store: SandboxStore) {
    const hasAdmin = store.users.some((u) => u.role_code === 'admin');
    const hasDb = Boolean(cfg.supabase_host && cfg.supabase_password);
    const hasJwt = Boolean(cfg.jwt_secret_key && cfg.jwt_refresh_secret_key);
    const persistence = configStore.getPersistenceDetails();
    const startup = configStore.getStartupRestoreState();

    const databaseStatus: 'Connected' | 'Disconnected' | 'Not Configured' = !cfg.supabase_host
      ? 'Not Configured'
      : cfg.last_db_test_ok
        ? 'Connected'
        : 'Disconnected';

    const fastapiStatus: 'Online' | 'Offline' | 'Not Configured' = !cfg.fastapi_base_url
      ? 'Not Configured'
      : cfg.last_backend_test_ok
        ? 'Online'
        : 'Offline';

    const overallStatus: 'Online' | 'Offline' | 'Configuration Required' =
      hasDb && hasJwt && Boolean(cfg.fastapi_base_url)
        ? databaseStatus === 'Connected' && fastapiStatus === 'Online'
          ? 'Online'
          : 'Offline'
        : 'Configuration Required';

    const maskedHost = cfg.supabase_host
      ? `${cfg.supabase_host.slice(0, 6)}••••${cfg.supabase_host.slice(-14)}:${cfg.supabase_port}`
      : '';

    const tablesVerifiedStrict =
      Boolean(cfg.tables_verified) &&
      cfg.verified_tables_count === REQUIRED_TABLES_20.length &&
      Array.isArray(cfg.missing_tables) &&
      cfg.missing_tables.length === 0;

    const databaseSetupComplete =
      hasDb && Boolean(cfg.last_db_test_ok) && tablesVerifiedStrict;

    return {
      has_database_config: hasDb,
      masked_db_host: maskedHost,
      supabase_host: cfg.supabase_host,
      supabase_port: cfg.supabase_port,
      supabase_user: cfg.supabase_user,
      supabase_db_name: cfg.supabase_db_name,
      db_ssl_require: cfg.db_ssl_require,
      db_pooler_mode: cfg.db_pooler_mode,
      db_project_label: cfg.db_project_label || 'NEW Supabase Project',
      is_new_supabase_project: Boolean(cfg.is_new_supabase_project),
      has_jwt_secrets: hasJwt,
      has_bootstrap_token: Boolean(cfg.setup_bootstrap_token),
      fastapi_base_url: cfg.fastapi_base_url,
      cors_origins: cfg.cors_origins,
      sql_migration_confirmed: tablesVerifiedStrict,
      tables_verified: tablesVerifiedStrict,
      database_setup_complete: databaseSetupComplete,
      required_tables: [...REQUIRED_TABLES_20],
      verified_tables_count: Number(cfg.verified_tables_count || 0),
      verified_tables_list: Array.isArray(cfg.verified_tables_list) ? cfg.verified_tables_list : [],
      missing_tables: Array.isArray(cfg.missing_tables)
        ? cfg.missing_tables
        : [...REQUIRED_TABLES_20],
      last_table_verify_at: cfg.last_table_verify_at,
      last_table_verify_message: cfg.last_table_verify_message,
      last_db_test_ok: cfg.last_db_test_ok,
      last_db_test_message: cfg.last_db_test_message,
      last_db_test_at: cfg.last_db_test_at,
      db_tls_diagnostics:
        cfg.last_db_tls_diagnostics || configStore.getCurrentTlsTrustDiagnostics(),
      last_backend_test_ok: cfg.last_backend_test_ok,
      last_backend_test_message: cfg.last_backend_test_message,
      last_backend_test_at: cfg.last_backend_test_at,
      updated_at: cfg.last_saved_at,
      last_saved_at: cfg.last_saved_at,
      database_status: databaseStatus,
      fastapi_status: fastapiStatus,
      overall_status: overallStatus,
      persistence_verified: persistence.persistence_verified,
      persistence_details: persistence,
      startup_restore: startup,
      key_migration: configStore.getKeyMigrationStatus(),
      artifacts: {
        has_sql_migration: fs.existsSync(path.resolve(process.cwd(), 'migrations/001_initial_schema.sql')),
        has_dockerfile: fs.existsSync(path.resolve(process.cwd(), 'backend/Dockerfile')),
        has_render_blueprint: fs.existsSync(path.resolve(process.cwd(), 'render.yaml')),
        has_procfile: fs.existsSync(path.resolve(process.cwd(), 'backend/Procfile')),
      },
      readiness: {
        admin_initialized: hasAdmin,
        db_configured: hasDb,
        db_tls_verified: Boolean(cfg.last_db_test_ok),
        sql_migration_confirmed: tablesVerifiedStrict,
        tables_verified: tablesVerifiedStrict,
        database_setup_complete: databaseSetupComplete,
        secrets_generated: hasJwt,
        fastapi_healthy: Boolean(cfg.last_backend_test_ok),
        persistence_verified: persistence.persistence_verified,
      },
    };
  }

  app.get('/api/v1/admin/infra/status', requireAuth, requireAdmin, (_req, res) => {
    const cfg = configStore.readConfig();
    const store = readStore();
    res.json(buildMaskedStatus(cfg, store));
  });

  app.get('/api/v1/admin/infra/migration-sql', requireAuth, requireAdmin, (_req, res) => {
    const sqlPath = path.resolve(process.cwd(), 'migrations/001_initial_schema.sql');
    if (!fs.existsSync(sqlPath)) {
      return res.status(404).json({ detail: 'Migration SQL file not found.' });
    }
    return res.json({
      filename: 'migrations/001_initial_schema.sql',
      sql: fs.readFileSync(sqlPath, 'utf-8'),
    });
  });

  app.put('/api/v1/admin/infra/database', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    if (req.body?.db_ssl_require === false) {
      return res.status(400).json({
        detail:
          'Disabling SSL/TLS verification is prohibited. RG Studio requires verified TLS (verify-full) for Supabase PostgreSQL.',
      });
    }

    const rawUri = String(req.body?.connection_uri || '').trim();
    let nextHost = '';
    let nextPort = 6543;
    let nextUser = 'postgres';
    let nextDbName = 'postgres';
    let nextPassword: string | undefined;
    let detectedPooler: boolean | undefined;

    if (rawUri) {
      try {
        const parsed = parsePostgresConnectionUri(rawUri);
        nextHost = parsed.host;
        nextPort = parsed.port;
        nextUser = parsed.user;
        nextDbName = parsed.database;
        nextPassword = parsed.password;
        detectedPooler = parsed.isPooler;
      } catch (err) {
        return res.status(400).json({
          detail: err instanceof Error ? err.message : 'Invalid PostgreSQL connection URI format.',
        });
      }
    } else {
      nextHost = String(req.body?.supabase_host || '').trim();
      nextPort = Number(req.body?.supabase_port || 6543);
      nextUser = String(req.body?.supabase_user || 'postgres').trim() || 'postgres';
      nextDbName = String(req.body?.supabase_db_name || 'postgres').trim() || 'postgres';
      const password = typeof req.body?.supabase_password === 'string' ? req.body.supabase_password : '';

      if (!nextHost || !Number.isInteger(nextPort) || nextPort < 1 || nextPort > 65535) {
        return res.status(400).json({ detail: 'Valid Supabase PostgreSQL host and port are required.' });
      }
      if (password) {
        nextPassword = password;
      }
    }

    const updated = configStore.saveConfig(
      {
        supabase_host: nextHost,
        supabase_port: nextPort,
        supabase_user: nextUser,
        supabase_db_name: nextDbName,
        db_ssl_require: true,
        db_pooler_mode:
          typeof req.body?.db_pooler_mode === 'boolean' ? req.body.db_pooler_mode : detectedPooler,
        db_project_label: 'NEW Supabase Project',
        is_new_supabase_project: true,
        explicit_db_reset: false,
        last_db_test_ok: null,
        last_db_test_message: null,
        last_db_test_at: null,
        last_db_tls_diagnostics: null,
        sql_migration_confirmed: false,
        tables_verified: false,
        verified_tables_count: 0,
        verified_tables_list: [],
        missing_tables: [...REQUIRED_TABLES_20],
        last_table_verify_at: null,
        last_table_verify_message: null,
      },
      nextPassword ? { supabase_password: nextPassword } : undefined,
      { markSavedNow: true }
    );

    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_NEW_SUPABASE_TARGET_SAVED',
      record_type: 'app_settings',
      record_id: null,
      details: `Encrypted and saved NEW Supabase project target (${updated.supabase_host}:${updated.supabase_port}, db=${updated.supabase_db_name}). JWT keys & master encryption key preserved.`,
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.post('/api/v1/admin/infra/database/reset-target', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const updated = configStore.resetDatabaseTargetOnly();
    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_DATABASE_TARGET_RESET',
      record_type: 'app_settings',
      record_id: null,
      details:
        'Cleared previous Supabase database target for connecting a NEW Supabase project. Admin account, RBAC, JWT secrets, encryption key, and FastAPI URL preserved.',
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.post('/api/v1/admin/infra/test-db', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
    const cfg = configStore.readConfig();
    if (!cfg.supabase_host || !cfg.supabase_password) {
      return res.status(400).json({
        detail: 'Save your NEW Supabase hostname, username, database name, and password before testing connection.',
      });
    }
    const result = await configStore.testPostgresConnection(cfg);
    const updated = configStore.saveConfig(
      {
        last_db_test_ok: result.ok,
        last_db_test_message: result.message,
        last_db_test_at: new Date().toISOString(),
        last_db_tls_diagnostics: result.diagnostics,
      },
      undefined,
      { markSavedNow: false, preserveVerification: true }
    );

    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_DB_CONNECTION_TESTED',
      record_type: 'app_settings',
      record_id: null,
      details: `${result.ok ? 'PASS' : 'FAIL'}: ${result.message}`,
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.put('/api/v1/admin/infra/db-ca', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const caPem = String(req.body?.ca_pem || '');
      const diag = configStore.saveCustomDbCaCertificate(caPem);
      const updated = configStore.saveConfig(
        { last_db_tls_diagnostics: diag },
        undefined,
        { markSavedNow: false, preserveVerification: true }
      );
      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_DB_CA_UPDATED',
        record_type: 'app_settings',
        record_id: null,
        details: `Saved protected server-side PostgreSQL CA certificate (${diag.custom_ca_fingerprint256 || 'verified'}).`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);
      return res.json(buildMaskedStatus(updated, store));
    } catch (err) {
      return res.status(400).json({
        detail: err instanceof Error ? err.message : 'Unable to save PostgreSQL CA certificate.',
      });
    }
  });

  app.delete('/api/v1/admin/infra/db-ca', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const diag = configStore.clearCustomDbCaCertificate();
    const updated = configStore.saveConfig(
      { last_db_tls_diagnostics: diag },
      undefined,
      { markSavedNow: false, preserveVerification: true }
    );
    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_DB_CA_REMOVED',
      record_type: 'app_settings',
      record_id: null,
      details: 'Removed optional custom PostgreSQL CA certificate; using System Roots + bundled Supabase Root 2021 CA.',
      created_at: new Date().toISOString(),
    });
    writeStore(store);
    return res.json(buildMaskedStatus(updated, store));
  });

  app.post('/api/v1/admin/infra/verify-tables', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
    const cfg = configStore.readConfig();
    if (!cfg.supabase_host || !cfg.supabase_password) {
      return res.status(400).json({
        detail: 'Save and test your NEW Supabase connection before verifying the 20 tables.',
      });
    }
    const check = await configStore.verifyRequiredTables(cfg);
    const updated = configStore.saveConfig(
      {
        tables_verified: check.ok,
        sql_migration_confirmed: check.ok,
        verified_tables_count: check.found_count,
        verified_tables_list: check.found_tables,
        missing_tables: check.missing_tables,
        last_table_verify_at: new Date().toISOString(),
        last_table_verify_message: check.message,
        last_db_tls_diagnostics: check.diagnostics,
      },
      undefined,
      { markSavedNow: false, preserveVerification: true }
    );

    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_20_TABLES_VERIFIED',
      record_type: 'app_settings',
      record_id: null,
      details: `${check.ok ? 'COMPLETE (20/20)' : `INCOMPLETE (${check.found_count}/20)`}: ${check.message}`,
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.post('/api/v1/admin/infra/generate-secrets', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const current = configStore.readConfig();
    const forceRegenerate = Boolean(req.body?.force_regenerate);

    // Do NOT unnecessarily overwrite or regenerate existing working JWT secrets unless explicitly requested
    if (current.jwt_secret_key && current.jwt_refresh_secret_key && !forceRegenerate) {
      const store = readStore();
      return res.json({
        ...buildMaskedStatus(current, store),
        preserved_existing_secrets: true,
      });
    }

    const updated = configStore.saveConfig(
      {},
      {
        jwt_secret_key: crypto.randomBytes(32).toString('hex'),
        jwt_refresh_secret_key: crypto.randomBytes(32).toString('hex'),
        setup_bootstrap_token: crypto.randomBytes(24).toString('hex'),
      },
      { markSavedNow: true }
    );

    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: forceRegenerate ? 'INFRA_SECRETS_ROTATED' : 'INFRA_SECRETS_GENERATED',
      record_type: 'app_settings',
      record_id: null,
      details: forceRegenerate
        ? 'Rotated encrypted server-side JWT access/refresh keys and bootstrap token.'
        : 'Generated encrypted server-side JWT access/refresh keys and bootstrap token.',
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.put('/api/v1/admin/infra/deployment', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const apiUrl = String(req.body?.fastapi_base_url || '').trim().replace(/\/+$/, '');
    const corsOrigins = String(req.body?.cors_origins || '').trim();

    if (apiUrl) {
      if (!apiUrl.startsWith('https://') && !apiUrl.startsWith('http://')) {
        return res.status(400).json({ detail: 'Backend URL must start with https:// (or http:// for local testing).' });
      }
      if (apiUrl.includes('localhost:3000') || apiUrl.includes('127.0.0.1:3000')) {
        return res.status(400).json({
          detail: 'Port 3000 is the AI Studio web preview, not the FastAPI backend API URL.',
        });
      }
    }

    const updated = configStore.saveConfig(
      {
        fastapi_base_url: apiUrl,
        cors_origins: corsOrigins,
        last_backend_test_ok: null,
        last_backend_test_message: null,
      },
      undefined,
      { markSavedNow: true }
    );

    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_DEPLOYMENT_UPDATED',
      record_type: 'app_settings',
      record_id: null,
      details: `Saved permanent backend URL (${apiUrl || 'blank'}) and migration status.`,
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.post('/api/v1/admin/infra/test-backend', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
    const cfg = configStore.readConfig();
    if (!cfg.fastapi_base_url) {
      return res.status(400).json({ detail: 'Enter your deployed FastAPI HTTPS URL first.' });
    }
    const result = await configStore.testFastApiHealth(cfg.fastapi_base_url);
    const updated = configStore.saveConfig(
      {
        last_backend_test_ok: result.ok,
        last_backend_test_message: result.message,
        last_backend_test_at: new Date().toISOString(),
      },
      undefined,
      { markSavedNow: false, preserveVerification: true }
    );

    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_BACKEND_TESTED',
      record_type: 'app_settings',
      record_id: null,
      details: `${result.ok ? 'ONLINE' : 'OFFLINE'}: ${result.message}`,
      created_at: new Date().toISOString(),
    });
    writeStore(store);

    return res.json(buildMaskedStatus(updated, store));
  });

  app.post('/api/v1/admin/infra/verify-persistence', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const verification = configStore.verifyPersistentStorage();
      const cfg = configStore.readConfig();
      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_PERSISTENCE_CHECKED',
        record_type: 'app_settings',
        record_id: null,
        details: `Storage read/decrypt=${verification.write_read_decrypt_ok}, survived_restart=${verification.survived_process_restart} (${verification.storage_durability}).`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);
      return res.json(buildMaskedStatus(cfg, store));
    } catch (err) {
      return res.status(500).json({
        detail: `Persistent storage verification failed: ${
          err instanceof Error ? err.message : 'unknown error'
        }`,
      });
    }
  });

  app.post('/api/v1/admin/infra/backup/export', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const passphrase = String(req.body?.passphrase || '');
      const { filename, content } = configStore.exportEncryptedBackup(passphrase);
      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_BACKUP_EXPORTED',
        record_type: 'app_settings',
        record_id: null,
        details: `Exported AES-256-GCM encrypted configuration backup (${filename}).`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);

      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'no-store');
      return res.send(content);
    } catch (err) {
      return res.status(400).json({
        detail: err instanceof Error ? err.message : 'Unable to export encrypted backup.',
      });
    }
  });

  app.post('/api/v1/admin/infra/backup/restore', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
    try {
      const backupJson = String(req.body?.backup_json || '');
      const passphrase = String(req.body?.passphrase || '');
      configStore.restoreEncryptedBackup(backupJson, passphrase);
      await configStore.runStartupRestore();
      const cfg = configStore.readConfig();

      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_BACKUP_RESTORED',
        record_type: 'app_settings',
        record_id: null,
        details: 'Restored encrypted configuration backup and ran connectivity validation.',
        created_at: new Date().toISOString(),
      });
      writeStore(store);
      return res.json(buildMaskedStatus(cfg, store));
    } catch (err) {
      return res.status(400).json({
        detail: err instanceof Error ? err.message : 'Unable to restore encrypted backup.',
      });
    }
  });

  // --- Safe RG_CONFIG_ENCRYPTION_KEY Migration Workflow (Admin Only, Zero Secret Exposure) ---
  app.post('/api/v1/admin/infra/key-migration/prepare', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const backupPassphrase = String(req.body?.backup_passphrase || '');
      const customNewKey = typeof req.body?.custom_new_key === 'string' ? req.body.custom_new_key : undefined;
      const migration = configStore.prepareKeyMigration({
        backupPassphrase,
        initiatedBy: req.actor!.username,
        customNewKey,
      });
      const cfg = configStore.readConfig();
      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_KEY_MIGRATION_PREPARED',
        record_type: 'app_settings',
        record_id: null,
        details: `Staged RG_CONFIG_ENCRYPTION_KEY migration (${migration.staged?.old_key_fingerprint} -> ${migration.staged?.new_key_fingerprint}) with encrypted backup & decryption verification. Old key remains active until confirmed.`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);
      return res.json(buildMaskedStatus(cfg, store));
    } catch (err) {
      return res.status(400).json({
        detail: err instanceof Error ? err.message : 'Unable to stage encryption key migration.',
      });
    }
  });

  app.post('/api/v1/admin/infra/key-migration/activate', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const confirmationPhrase = String(req.body?.confirmation_phrase || '');
      const migration = configStore.activateKeyMigration({
        confirmationPhrase,
        initiatedBy: req.actor!.username,
      });
      const cfg = configStore.readConfig();
      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_KEY_MIGRATION_ACTIVATED',
        record_type: 'app_settings',
        record_id: null,
        details: `Activated new 256-bit RG_CONFIG_ENCRYPTION_KEY (fingerprint=${migration.active_key_fingerprint}, migrated_fields=${migration.last_migration?.migrated_secret_fields.length || 0}). Post-activation decryption verified.`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);
      return res.json(buildMaskedStatus(cfg, store));
    } catch (err) {
      return res.status(400).json({
        detail: err instanceof Error ? err.message : 'Unable to activate new encryption key.',
      });
    }
  });

  app.post('/api/v1/admin/infra/key-migration/cancel', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    configStore.cancelKeyMigration();
    const cfg = configStore.readConfig();
    const store = readStore();
    store.audit_logs.unshift({
      id: crypto.randomUUID(),
      actor_user_id: req.actor!.id,
      actor_username: req.actor!.username,
      action: 'INFRA_KEY_MIGRATION_CANCELLED',
      record_type: 'app_settings',
      record_id: null,
      details: 'Cancelled staged encryption key migration. Existing active key and encrypted config kept untouched.',
      created_at: new Date().toISOString(),
    });
    writeStore(store);
    return res.json(buildMaskedStatus(cfg, store));
  });

  app.post('/api/v1/admin/infra/key-migration/download-backup', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const { filename, content } = configStore.getPreMigrationBackupFile();
      const store = readStore();
      store.audit_logs.unshift({
        id: crypto.randomUUID(),
        actor_user_id: req.actor!.id,
        actor_username: req.actor!.username,
        action: 'INFRA_PRE_MIGRATION_BACKUP_DOWNLOADED',
        record_type: 'app_settings',
        record_id: null,
        details: `Downloaded passphrase-encrypted pre-migration recovery backup (${filename}).`,
        created_at: new Date().toISOString(),
      });
      writeStore(store);

      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'no-store');
      return res.send(content);
    } catch (err) {
      return res.status(400).json({
        detail: err instanceof Error ? err.message : 'Unable to download pre-migration backup.',
      });
    }
  });

  app.post('/api/v1/admin/infra/download-env', requireAuth, requireAdmin, (_req, res) => {
    const cfg = configStore.readConfig();
    if (!cfg.supabase_host || !cfg.supabase_password) {
      return res.status(400).json({ detail: 'Save Supabase host and password first.' });
    }
    if (!cfg.jwt_secret_key || !cfg.jwt_refresh_secret_key) {
      return res.status(400).json({ detail: 'Generate server security secrets first.' });
    }
    const migration = configStore.getKeyMigrationStatus();
    const encUser = encodeURIComponent(cfg.supabase_user);
    const dbName = cfg.supabase_db_name || 'postgres';
    const asyncUrl = `postgresql+asyncpg://${encUser}:__ENTER_NEW_SUPABASE_PASSWORD__@${cfg.supabase_host}:${cfg.supabase_port}/${dbName}`;
    const syncPort = cfg.supabase_port === 6543 ? 5432 : cfg.supabase_port;
    const syncUrl = `postgresql+psycopg://${encUser}:__ENTER_NEW_SUPABASE_PASSWORD__@${cfg.supabase_host}:${syncPort}/${dbName}?sslmode=verify-full`;

    // Strictly redact passwords, JWT secrets, and encryption keys from HTTP responses
    const envText = [
      '# RG STUDIO MANAGEMENT SYSTEM — SAFE HOSTING ENV TEMPLATE (SECRETS REDACTED)',
      '# Fill secret values directly inside your hosting Secret Manager (Render / Railway).',
      `# Active RG_CONFIG_ENCRYPTION_KEY fingerprint: ${migration.active_key_fingerprint}`,
      'RG_ENVIRONMENT=production',
      'RG_APP_NAME=RG Studio Management System API',
      'RG_API_V1_PREFIX=/api/v1',
      `RG_DATABASE_URL=${asyncUrl}`,
      `RG_DATABASE_SYNC_URL=${syncUrl}`,
      'RG_DB_SSL_REQUIRE=true',
      `RG_DB_POOLER_MODE=${cfg.db_pooler_mode ? 'true' : 'false'}`,
      'RG_DB_SSL_CA_FILE=certs/supabase-prod-ca-2021.crt',
      'RG_JWT_SECRET_KEY=__SET_IN_HOSTING_SECRET_MANAGER__',
      'RG_JWT_REFRESH_SECRET_KEY=__SET_IN_HOSTING_SECRET_MANAGER__',
      'RG_SETUP_BOOTSTRAP_TOKEN=__SET_IN_HOSTING_SECRET_MANAGER__',
      'RG_CONFIG_ENCRYPTION_KEY=__SET_OR_GENERATE_256BIT_KEY_IN_HOSTING_SECRET_MANAGER__',
      `RG_CORS_ORIGINS=${cfg.cors_origins}`,
      '',
    ].join('\n');

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="rgstudio-backend-template.env"');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(envText);
  });

  // Ensure unmatched /api/* requests and server errors always return JSON (never HTML)
  app.use('/api', (req, res) => {
    res.status(404).json({
      detail: `API endpoint not found: ${req.method} ${req.originalUrl}`,
    });
  });

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (!req.path.startsWith('/api')) {
      return next(err);
    }
    const status =
      typeof err === 'object' &&
      err !== null &&
      'status' in err &&
      typeof (err as { status?: unknown }).status === 'number'
        ? (err as { status: number }).status
        : 500;
    const message =
      err instanceof SyntaxError
        ? 'Invalid JSON request payload.'
        : err instanceof Error
          ? err.message
          : 'Internal Phase 1 Sandbox API error.';
    return res.status(status).json({ detail: message });
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  // Restore encrypted config synchronously before listening, then validate remote links asynchronously
  configStore.initBootRestoreSync();
  void configStore.runStartupRestore();

  app.listen(3000, '0.0.0.0', () => {
    console.log('RG Studio Management System Phase 1 Workbench listening on port 3000');
  });
}

startServer();
