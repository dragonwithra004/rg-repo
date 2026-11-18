import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { Client as PgClient } from 'pg';

export const REQUIRED_TABLES_20 = [
  'roles',
  'permissions',
  'role_permissions',
  'users',
  'employees',
  'mobiles',
  'sim_cards',
  'gmail_accounts',
  'youtube_channels',
  'employee_teams',
  'team_members',
  'company_channels',
  'mobile_assignments',
  'sim_assignments',
  'gmail_assignments',
  'channel_assignments',
  'audit_logs',
  'app_settings',
  'backup_logs',
  'employee_requests',
] as const;

export interface InfraMetadata {
  supabase_host: string;
  supabase_port: number;
  supabase_user: string;
  supabase_db_name: string;
  db_ssl_require: boolean;
  db_pooler_mode: boolean;
  db_project_label: string;
  is_new_supabase_project: boolean;
  explicit_db_reset: boolean;
  fastapi_base_url: string;
  cors_origins: string;
  sql_migration_confirmed: boolean;
  tables_verified: boolean;
  verified_tables_count: number;
  verified_tables_list: string[];
  missing_tables: string[];
  last_table_verify_at: string | null;
  last_table_verify_message: string | null;
  last_db_test_ok: boolean | null;
  last_db_test_message: string | null;
  last_db_test_at: string | null;
  last_backend_test_ok: boolean | null;
  last_backend_test_message: string | null;
  last_backend_test_at: string | null;
}

export interface InfraSecrets {
  supabase_password: string;
  jwt_secret_key: string;
  jwt_refresh_secret_key: string;
  setup_bootstrap_token: string;
  sandbox_jwt_secret: string;
}

export interface DecryptedInfraConfig extends InfraMetadata, InfraSecrets {
  last_saved_at: string | null;
  saved_in_boot_id: string | null;
  persistence_verified: boolean;
  persistence_verified_at: string | null;
  verified_restarts_count: number;
  master_key_fingerprint: string | null;
}

interface EncryptedEnvelope {
  alg: 'aes-256-gcm';
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface KeyMigrationRecord {
  activated_at: string;
  initiated_by: string;
  old_key_fingerprint: string;
  new_key_fingerprint: string;
  migrated_secret_fields: string[];
  post_activation_verified: boolean;
  backup_preserved: boolean;
}

export interface KeyMigrationStatus {
  active_key_fingerprint: string;
  key_source: 'env-master-key' | 'local-keyfile-fallback' | 'migrated-server-key';
  hosting_env_synced: boolean;
  hosting_env_notice: string | null;
  migration_state: 'idle' | 'staged_verified' | 'activated';
  has_pre_migration_backup: boolean;
  staged: {
    staged_at: string;
    initiated_by: string;
    old_key_fingerprint: string;
    new_key_fingerprint: string;
    migrated_secret_fields: string[];
    decryption_verified: boolean;
    verified_at: string;
    pre_migration_backup_created: boolean;
    pre_migration_backup_sha256: string;
  } | null;
  last_migration: KeyMigrationRecord | null;
}

interface StagedKeyMigrationFile {
  format: 'rgstudio-key-migration-stage-v1';
  staged_at: string;
  initiated_by: string;
  old_key_fingerprint: string;
  new_key_fingerprint: string;
  new_key_hex: string;
  pre_migration_backup_path: string;
  pre_migration_backup_sha256: string;
  migrated_secret_fields: string[];
  staged_envelope: EncryptedEnvelope;
  decryption_verified: boolean;
  verified_at: string;
  secret_hashes: Record<string, string>;
}

interface PersistedConfigFile {
  format: 'rgstudio-server-config-v2';
  master_key_fingerprint?: string | null;
  last_migration?: KeyMigrationRecord | null;
  saved_in_boot_id: string | null;
  last_saved_at: string | null;
  persistence_verified: boolean;
  persistence_verified_at: string | null;
  verified_restarts_count: number;
  metadata: InfraMetadata;
  encrypted_secrets: EncryptedEnvelope | null;
}

export interface StartupRestoreState {
  restored_at: string;
  boot_id_short: string;
  overall_status: 'Online' | 'Offline' | 'Configuration Required';
  fastapi_status: 'Online' | 'Offline' | 'Not Configured';
  database_status: 'Connected' | 'Disconnected' | 'Not Configured';
  message: string;
}

export interface PersistenceVerificationResult {
  write_read_decrypt_ok: boolean;
  survived_process_restart: boolean;
  persistence_verified: boolean;
  verified_restarts_count: number;
  persistence_verified_at: string | null;
  storage_durability: 'durable-volume' | 'env-managed' | 'ephemeral-container';
  storage_location_label: string;
  key_source: 'env-master-key' | 'local-keyfile-fallback' | 'migrated-server-key';
  env_secrets_active: boolean;
  warning: string | null;
}

const CURRENT_BOOT_ID = crypto.randomUUID();
const CONFIG_FILENAME = 'rgstudio-config.enc.json';
const LEGACY_CONFIG_FILENAME = '.rgstudio-server-config.json';
const MASTER_KEY_FILENAME = '.rgstudio-master.key';
const PREV_MASTER_KEY_FILENAME = '.rgstudio-master.key.prev';
const KEY_MIGRATION_STAGE_FILENAME = '.rgstudio-key-migration.stage.json';
const PRE_MIGRATION_BACKUP_FILENAME = '.rgstudio-pre-migration-backup.rgcfg';
const HOSTING_SECRETS_ENV_FILENAME = '.rgstudio-hosting-secrets.env';
const CONFIG_AAD = Buffer.from('rgstudio-server-config-v2');
const BACKUP_AAD = Buffer.from('rgstudio-encrypted-backup-v1');

function resolveStorageDirectory(): {
  dir: string;
  durability: 'durable-volume' | 'ephemeral-container';
  label: string;
  warning: string | null;
} {
  const configuredDir = String(process.env.RG_PERSISTENT_DATA_DIR || '').trim();
  if (configuredDir) {
    try {
      fs.mkdirSync(configuredDir, { recursive: true });
      const probePath = path.join(configuredDir, '.rgstudio-write-test');
      fs.writeFileSync(probePath, 'ok', 'utf-8');
      fs.unlinkSync(probePath);
      return {
        dir: configuredDir,
        durability: 'durable-volume',
        label: `Persistent volume (${configuredDir})`,
        warning: null,
      };
    } catch (err) {
      return {
        dir: process.cwd(),
        durability: 'ephemeral-container',
        label: `Container workspace fallback (${configuredDir} unavailable)`,
        warning: `Configured RG_PERSISTENT_DATA_DIR (${configuredDir}) is not writable: ${
          err instanceof Error ? err.message : 'permission error'
        }. Falling back to container filesystem.`,
      };
    }
  }

  return {
    dir: process.cwd(),
    durability: 'ephemeral-container',
    label: 'Container filesystem (AI Studio preview / local workspace)',
    warning:
      'Running on container filesystem without RG_PERSISTENT_DATA_DIR or platform env secrets. Settings survive process restarts on this machine, but AI Studio preview containers may reset on rebuild. Export an Encrypted Backup (.rgcfg) or configure Render/Railway Environment Variables for permanent production hosting.',
  };
}

function computeKeyFingerprint(keyBuf: Buffer): string {
  return crypto.createHash('sha256').update(keyBuf).digest('hex').slice(0, 12);
}

function deriveKeyCandidatesFromSecret(raw: string): Buffer[] {
  const candidates: Buffer[] = [];
  if (/^[a-fA-F0-9]{64}$/.test(raw)) {
    candidates.push(Buffer.from(raw, 'hex'));
  }
  candidates.push(
    Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(raw, 'utf-8'),
        Buffer.from('rgstudio-config-salt-v1', 'utf-8'),
        Buffer.from('aes-256-gcm-master', 'utf-8'),
        32
      )
    )
  );
  return candidates;
}

function loadHostingEnvOverride(dir: string): string {
  const hostingEnvPath = path.join(dir, HOSTING_SECRETS_ENV_FILENAME);
  if (!fs.existsSync(hostingEnvPath)) return '';
  try {
    const lines = fs.readFileSync(hostingEnvPath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^RG_CONFIG_ENCRYPTION_KEY=(.+)$/);
      if (m && m[1].trim().length >= 16) {
        return m[1].trim();
      }
    }
  } catch {
    // Ignore unreadable file
  }
  return '';
}

function getMasterKey(expectedFingerprint?: string | null): {
  key: Buffer;
  fingerprint: string;
  source: 'env-master-key' | 'local-keyfile-fallback' | 'migrated-server-key';
  hostingEnvSynced: boolean;
  dirInfo: ReturnType<typeof resolveStorageDirectory>;
} {
  const dirInfo = resolveStorageDirectory();
  const keyFilePath = path.join(dirInfo.dir, MASTER_KEY_FILENAME);
  const envKey = String(process.env.RG_CONFIG_ENCRYPTION_KEY || '').trim();
  const prevEnvKey = String(process.env.RG_CONFIG_ENCRYPTION_KEY_PREVIOUS || '').trim();

  // If the encrypted config specifies a master_key_fingerprint, match against hosting env first, then rotated keyfile
  if (expectedFingerprint) {
    if (envKey.length >= 16) {
      for (const candidate of deriveKeyCandidatesFromSecret(envKey)) {
        const fp = computeKeyFingerprint(candidate);
        if (fp === expectedFingerprint) {
          return {
            key: candidate,
            fingerprint: fp,
            source: 'env-master-key',
            hostingEnvSynced: true,
            dirInfo,
          };
        }
      }
    }

    if (fs.existsSync(keyFilePath)) {
      const kfHex = fs.readFileSync(keyFilePath, 'utf-8').trim();
      if (/^[a-fA-F0-9]{64}$/.test(kfHex)) {
        const kfBuf = Buffer.from(kfHex, 'hex');
        const fp = computeKeyFingerprint(kfBuf);
        if (fp === expectedFingerprint) {
          return {
            key: kfBuf,
            fingerprint: fp,
            source: envKey ? 'migrated-server-key' : 'local-keyfile-fallback',
            hostingEnvSynced: envKey.length === 0,
            dirInfo,
          };
        }
      }
    }

    if (prevEnvKey.length >= 16) {
      for (const candidate of deriveKeyCandidatesFromSecret(prevEnvKey)) {
        const fp = computeKeyFingerprint(candidate);
        if (fp === expectedFingerprint) {
          return {
            key: candidate,
            fingerprint: fp,
            source: 'env-master-key',
            hostingEnvSynced: false,
            dirInfo,
          };
        }
      }
    }
  }

  // Default priority: synced hosting env override -> process.env -> local keyfile
  if (envKey.length >= 16) {
    const derived = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(envKey, 'utf-8'),
        Buffer.from('rgstudio-config-salt-v1', 'utf-8'),
        Buffer.from('aes-256-gcm-master', 'utf-8'),
        32
      )
    );
    return {
      key: derived,
      fingerprint: computeKeyFingerprint(derived),
      source: 'env-master-key',
      hostingEnvSynced: true,
      dirInfo,
    };
  }

  const hostingSavedKey = loadHostingEnvOverride(dirInfo.dir);
  if (/^[a-fA-F0-9]{64}$/.test(hostingSavedKey)) {
    const buf = Buffer.from(hostingSavedKey, 'hex');
    return {
      key: buf,
      fingerprint: computeKeyFingerprint(buf),
      source: 'migrated-server-key',
      hostingEnvSynced: true,
      dirInfo,
    };
  }

  // Fallback external keyfile stored separately from encrypted config JSON
  let keyHex = '';
  if (fs.existsSync(keyFilePath)) {
    keyHex = fs.readFileSync(keyFilePath, 'utf-8').trim();
  }
  if (!/^[a-fA-F0-9]{64}$/.test(keyHex)) {
    keyHex = crypto.randomBytes(32).toString('hex');
    const fd = fs.openSync(keyFilePath, 'w', 0o600);
    try {
      fs.writeSync(fd, `${keyHex}\n`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }
  const keyBuf = Buffer.from(keyHex, 'hex');
  return {
    key: keyBuf,
    fingerprint: computeKeyFingerprint(keyBuf),
    source: 'local-keyfile-fallback',
    hostingEnvSynced: true,
    dirInfo,
  };
}

function encryptJsonWithKey(payload: unknown, key: Buffer, aad: Buffer): EncryptedEnvelope {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptJsonWithKey<T>(envelope: EncryptedEnvelope, key: Buffer, aad: Buffer): T {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(envelope.iv, 'base64')
  );
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString('utf-8')) as T;
}

function defaultMetadata(): InfraMetadata {
  return {
    supabase_host: '',
    supabase_port: 6543,
    supabase_user: 'postgres',
    supabase_db_name: 'postgres',
    db_ssl_require: true,
    db_pooler_mode: true,
    db_project_label: 'NEW Supabase Project',
    is_new_supabase_project: true,
    explicit_db_reset: false,
    fastapi_base_url: '',
    cors_origins: '',
    sql_migration_confirmed: false,
    tables_verified: false,
    verified_tables_count: 0,
    verified_tables_list: [],
    missing_tables: [...REQUIRED_TABLES_20],
    last_table_verify_at: null,
    last_table_verify_message: null,
    last_db_test_ok: null,
    last_db_test_message: null,
    last_db_test_at: null,
    last_backend_test_ok: null,
    last_backend_test_message: null,
    last_backend_test_at: null,
  };
}

function defaultSecrets(): InfraSecrets {
  return {
    supabase_password: '',
    jwt_secret_key: '',
    jwt_refresh_secret_key: '',
    setup_bootstrap_token: '',
    sandbox_jwt_secret: '',
  };
}

function writeFileDurable(filePath: string, content: string): void {
  const tmpPath = `${filePath}.tmp.${process.pid}`;
  const fd = fs.openSync(tmpPath, 'w', 0o600);
  try {
    fs.writeSync(fd, content, 0, 'utf-8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, filePath);
}

export class PermanentConfigStore {
  private bootVerifiedCounted = false;
  private lastStartupRestore: StartupRestoreState = {
    restored_at: new Date().toISOString(),
    boot_id_short: CURRENT_BOOT_ID.slice(0, 8),
    overall_status: 'Configuration Required',
    fastapi_status: 'Not Configured',
    database_status: 'Not Configured',
    message: 'Startup restore pending.',
  };

  private readRawConfigFile(encPath: string): PersistedConfigFile | null {
    if (!fs.existsSync(encPath)) return null;
    try {
      return JSON.parse(fs.readFileSync(encPath, 'utf-8')) as PersistedConfigFile;
    } catch {
      return null;
    }
  }

  private getPaths() {
    const dirInfo = resolveStorageDirectory();
    const encPath = path.join(dirInfo.dir, CONFIG_FILENAME);
    const existingRaw = this.readRawConfigFile(encPath);
    const keyInfo = getMasterKey(existingRaw?.master_key_fingerprint ?? null);
    return {
      key: keyInfo.key,
      keyFingerprint: keyInfo.fingerprint,
      keySource: keyInfo.source,
      hostingEnvSynced: keyInfo.hostingEnvSynced,
      dirInfo: keyInfo.dirInfo,
      encPath,
      legacyPath: path.resolve(process.cwd(), LEGACY_CONFIG_FILENAME),
      stagePath: path.join(dirInfo.dir, KEY_MIGRATION_STAGE_FILENAME),
      preBackupPath: path.join(dirInfo.dir, PRE_MIGRATION_BACKUP_FILENAME),
      masterKeyPath: path.join(dirInfo.dir, MASTER_KEY_FILENAME),
      prevMasterKeyPath: path.join(dirInfo.dir, PREV_MASTER_KEY_FILENAME),
      hostingSecretsPath: path.join(dirInfo.dir, HOSTING_SECRETS_ENV_FILENAME),
    };
  }

  private migrateLegacyIfNeeded(): void {
    const { key, keyFingerprint, encPath, legacyPath } = this.getPaths();
    if (fs.existsSync(encPath) || !fs.existsSync(legacyPath)) {
      return;
    }
    try {
      const legacy = JSON.parse(fs.readFileSync(legacyPath, 'utf-8')) as Partial<DecryptedInfraConfig>;
      const meta: InfraMetadata = {
        ...defaultMetadata(),
        supabase_host: legacy.supabase_host || '',
        supabase_port: Number(legacy.supabase_port || 6543),
        supabase_user: legacy.supabase_user || 'postgres',
        supabase_db_name: legacy.supabase_db_name || 'postgres',
        db_ssl_require: legacy.db_ssl_require ?? true,
        db_pooler_mode: legacy.db_pooler_mode ?? true,
        fastapi_base_url: legacy.fastapi_base_url || '',
        cors_origins: legacy.cors_origins || '',
        sql_migration_confirmed: Boolean(legacy.sql_migration_confirmed),
        last_db_test_ok: legacy.last_db_test_ok ?? null,
        last_db_test_message: legacy.last_db_test_message ?? null,
        last_db_test_at: legacy.last_db_test_at ?? null,
        last_backend_test_ok: legacy.last_backend_test_ok ?? null,
        last_backend_test_message: legacy.last_backend_test_message ?? null,
        last_backend_test_at: legacy.last_backend_test_at ?? null,
      };
      const secrets: InfraSecrets = {
        supabase_password: legacy.supabase_password || '',
        jwt_secret_key: legacy.jwt_secret_key || '',
        jwt_refresh_secret_key: legacy.jwt_refresh_secret_key || '',
        setup_bootstrap_token: legacy.setup_bootstrap_token || '',
        sandbox_jwt_secret: legacy.sandbox_jwt_secret || '',
      };
      const payload: PersistedConfigFile = {
        format: 'rgstudio-server-config-v2',
        master_key_fingerprint: keyFingerprint,
        last_migration: null,
        saved_in_boot_id: null,
        last_saved_at: new Date().toISOString(),
        persistence_verified: false,
        persistence_verified_at: null,
        verified_restarts_count: 0,
        metadata: meta,
        encrypted_secrets: encryptJsonWithKey(secrets, key, CONFIG_AAD),
      };
      writeFileDurable(encPath, JSON.stringify(payload, null, 2));
      fs.unlinkSync(legacyPath);
    } catch {
      // Do not crash if legacy file was corrupted
    }
  }

  public readConfig(): DecryptedInfraConfig {
    this.migrateLegacyIfNeeded();
    const { key, keyFingerprint, encPath } = this.getPaths();
    const baseMeta = defaultMetadata();
    const baseSecrets = defaultSecrets();

    let fileRecord: PersistedConfigFile | null = null;
    if (fs.existsSync(encPath)) {
      try {
        fileRecord = JSON.parse(fs.readFileSync(encPath, 'utf-8')) as PersistedConfigFile;
        if (fileRecord.metadata) {
          Object.assign(baseMeta, fileRecord.metadata);
        }
        if (fileRecord.encrypted_secrets) {
          const decrypted = decryptJsonWithKey<Partial<InfraSecrets>>(
            fileRecord.encrypted_secrets,
            key,
            CONFIG_AAD
          );
          Object.assign(baseSecrets, decrypted);
        }
      } catch {
        // Keep defaults if decryption fails; caller detects unverified state
      }
    }

    // Non-destructive hydration from platform environment variables (Render/Railway) ONLY when missing
    this.hydrateMissingFromEnv(baseMeta, baseSecrets);

    return {
      ...baseMeta,
      ...baseSecrets,
      last_saved_at: fileRecord?.last_saved_at ?? null,
      saved_in_boot_id: fileRecord?.saved_in_boot_id ?? null,
      persistence_verified: Boolean(fileRecord?.persistence_verified),
      persistence_verified_at: fileRecord?.persistence_verified_at ?? null,
      verified_restarts_count: Number(fileRecord?.verified_restarts_count || 0),
      master_key_fingerprint: fileRecord?.master_key_fingerprint ?? keyFingerprint,
    };
  }

  private hydrateMissingFromEnv(meta: InfraMetadata, secrets: InfraSecrets): boolean {
    let changed = false;
    const envDbUrl = String(process.env.RG_DATABASE_URL || '').trim();
    if (!meta.explicit_db_reset && envDbUrl && (!meta.supabase_host || !secrets.supabase_password)) {
      try {
        const normalized = envDbUrl.replace(/^postgresql\+(asyncpg|psycopg):\/\//, 'postgresql://');
        const parsed = new URL(normalized);
        if (parsed.hostname && !meta.supabase_host) {
          meta.supabase_host = parsed.hostname;
          meta.supabase_port = parsed.port ? Number(parsed.port) : 6543;
          meta.supabase_user = decodeURIComponent(parsed.username || 'postgres');
          meta.supabase_db_name = parsed.pathname.replace(/^\//, '') || 'postgres';
          changed = true;
        }
        if (parsed.password && !secrets.supabase_password) {
          secrets.supabase_password = decodeURIComponent(parsed.password);
          changed = true;
        }
      } catch {
        // Ignore malformed env URL
      }
    }
    const envJwt = String(process.env.RG_JWT_SECRET_KEY || '').trim();
    if (envJwt && !secrets.jwt_secret_key && !envJwt.startsWith('dev-only-')) {
      secrets.jwt_secret_key = envJwt;
      changed = true;
    }
    const envRefreshJwt = String(process.env.RG_JWT_REFRESH_SECRET_KEY || '').trim();
    if (envRefreshJwt && !secrets.jwt_refresh_secret_key && !envRefreshJwt.startsWith('dev-only-')) {
      secrets.jwt_refresh_secret_key = envRefreshJwt;
      changed = true;
    }
    const envBootstrap = String(process.env.RG_SETUP_BOOTSTRAP_TOKEN || '').trim();
    if (envBootstrap && !secrets.setup_bootstrap_token) {
      secrets.setup_bootstrap_token = envBootstrap;
      changed = true;
    }
    const envApiUrl = String(process.env.RG_API_BASE_URL || '').trim().replace(/\/+$/, '');
    if (envApiUrl && !meta.fastapi_base_url) {
      meta.fastapi_base_url = envApiUrl;
      changed = true;
    }
    const envCors = String(process.env.RG_CORS_ORIGINS || '').trim();
    if (envCors && !meta.cors_origins) {
      meta.cors_origins = envCors;
      changed = true;
    }
    return changed;
  }

  public saveConfig(
    nextMeta: Partial<InfraMetadata>,
    nextSecrets?: Partial<InfraSecrets>,
    options: {
      markSavedNow?: boolean;
      preserveVerification?: boolean;
      clearSupabasePassword?: boolean;
    } = {}
  ): DecryptedInfraConfig {
    const current = this.readConfig();

    const mergedMeta: InfraMetadata = {
      supabase_host: nextMeta.supabase_host ?? current.supabase_host,
      supabase_port: nextMeta.supabase_port ?? current.supabase_port,
      supabase_user: nextMeta.supabase_user ?? current.supabase_user,
      supabase_db_name: nextMeta.supabase_db_name ?? current.supabase_db_name,
      db_ssl_require: nextMeta.db_ssl_require ?? current.db_ssl_require,
      db_pooler_mode: nextMeta.db_pooler_mode ?? current.db_pooler_mode,
      db_project_label: nextMeta.db_project_label ?? current.db_project_label,
      is_new_supabase_project:
        nextMeta.is_new_supabase_project ?? current.is_new_supabase_project,
      explicit_db_reset: nextMeta.explicit_db_reset ?? current.explicit_db_reset,
      fastapi_base_url: nextMeta.fastapi_base_url ?? current.fastapi_base_url,
      cors_origins: nextMeta.cors_origins ?? current.cors_origins,
      sql_migration_confirmed: nextMeta.sql_migration_confirmed ?? current.sql_migration_confirmed,
      tables_verified: nextMeta.tables_verified ?? current.tables_verified,
      verified_tables_count: nextMeta.verified_tables_count ?? current.verified_tables_count,
      verified_tables_list: nextMeta.verified_tables_list ?? current.verified_tables_list,
      missing_tables: nextMeta.missing_tables ?? current.missing_tables,
      last_table_verify_at:
        nextMeta.last_table_verify_at !== undefined
          ? nextMeta.last_table_verify_at
          : current.last_table_verify_at,
      last_table_verify_message:
        nextMeta.last_table_verify_message !== undefined
          ? nextMeta.last_table_verify_message
          : current.last_table_verify_message,
      last_db_test_ok:
        nextMeta.last_db_test_ok !== undefined ? nextMeta.last_db_test_ok : current.last_db_test_ok,
      last_db_test_message:
        nextMeta.last_db_test_message !== undefined
          ? nextMeta.last_db_test_message
          : current.last_db_test_message,
      last_db_test_at:
        nextMeta.last_db_test_at !== undefined ? nextMeta.last_db_test_at : current.last_db_test_at,
      last_backend_test_ok:
        nextMeta.last_backend_test_ok !== undefined
          ? nextMeta.last_backend_test_ok
          : current.last_backend_test_ok,
      last_backend_test_message:
        nextMeta.last_backend_test_message !== undefined
          ? nextMeta.last_backend_test_message
          : current.last_backend_test_message,
      last_backend_test_at:
        nextMeta.last_backend_test_at !== undefined
          ? nextMeta.last_backend_test_at
          : current.last_backend_test_at,
    };

    const { key, keyFingerprint, encPath } = this.getPaths();
    const existingRaw = this.readRawConfigFile(encPath);

    const mergedSecrets: InfraSecrets = {
      supabase_password: options.clearSupabasePassword
        ? ''
        : nextSecrets?.supabase_password !== undefined && nextSecrets.supabase_password !== ''
          ? nextSecrets.supabase_password
          : current.supabase_password,
      jwt_secret_key:
        nextSecrets?.jwt_secret_key !== undefined && nextSecrets.jwt_secret_key !== ''
          ? nextSecrets.jwt_secret_key
          : current.jwt_secret_key,
      jwt_refresh_secret_key:
        nextSecrets?.jwt_refresh_secret_key !== undefined && nextSecrets.jwt_refresh_secret_key !== ''
          ? nextSecrets.jwt_refresh_secret_key
          : current.jwt_refresh_secret_key,
      setup_bootstrap_token:
        nextSecrets?.setup_bootstrap_token !== undefined && nextSecrets.setup_bootstrap_token !== ''
          ? nextSecrets.setup_bootstrap_token
          : current.setup_bootstrap_token,
      sandbox_jwt_secret:
        nextSecrets?.sandbox_jwt_secret !== undefined && nextSecrets.sandbox_jwt_secret !== ''
          ? nextSecrets.sandbox_jwt_secret
          : current.sandbox_jwt_secret,
    };

    const markSavedNow = options.markSavedNow !== false;
    const now = new Date().toISOString();

    const payload: PersistedConfigFile = {
      format: 'rgstudio-server-config-v2',
      master_key_fingerprint: existingRaw?.master_key_fingerprint ?? keyFingerprint,
      last_migration: existingRaw?.last_migration ?? null,
      saved_in_boot_id: markSavedNow ? CURRENT_BOOT_ID : current.saved_in_boot_id,
      last_saved_at: markSavedNow ? now : current.last_saved_at,
      persistence_verified: options.preserveVerification
        ? current.persistence_verified
        : markSavedNow
          ? false
          : current.persistence_verified,
      persistence_verified_at: options.preserveVerification
        ? current.persistence_verified_at
        : markSavedNow
          ? null
          : current.persistence_verified_at,
      verified_restarts_count: options.preserveVerification
        ? current.verified_restarts_count
        : markSavedNow
          ? 0
          : current.verified_restarts_count,
      metadata: mergedMeta,
      encrypted_secrets: encryptJsonWithKey(mergedSecrets, key, CONFIG_AAD),
    };

    writeFileDurable(encPath, JSON.stringify(payload, null, 2));
    return this.readConfig();
  }

  /**
   * Reset ONLY the Supabase database connection target for connecting a NEW Supabase project.
   * Strictly preserves JWT secrets, RG_CONFIG_ENCRYPTION_KEY, FastAPI URL, CORS, and all application data.
   */
  public resetDatabaseTargetOnly(): DecryptedInfraConfig {
    return this.saveConfig(
      {
        supabase_host: '',
        supabase_port: 6543,
        supabase_user: 'postgres',
        supabase_db_name: 'postgres',
        db_ssl_require: true,
        db_pooler_mode: true,
        db_project_label: 'NEW Supabase Project',
        is_new_supabase_project: true,
        explicit_db_reset: true,
        sql_migration_confirmed: false,
        tables_verified: false,
        verified_tables_count: 0,
        verified_tables_list: [],
        missing_tables: [...REQUIRED_TABLES_20],
        last_table_verify_at: null,
        last_table_verify_message: null,
        last_db_test_ok: null,
        last_db_test_message: null,
        last_db_test_at: null,
      },
      undefined,
      { markSavedNow: true, clearSupabasePassword: true }
    );
  }

  public getPersistenceDetails(): PersistenceVerificationResult {
    const { key, keySource, dirInfo, encPath } = this.getPaths();
    const cfg = this.readConfig();

    const envSecretsActive = Boolean(
      process.env.RG_DATABASE_URL &&
        process.env.RG_JWT_SECRET_KEY &&
        process.env.RG_JWT_REFRESH_SECRET_KEY
    );

    let writeReadDecryptOk = false;
    if (fs.existsSync(encPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(encPath, 'utf-8')) as PersistedConfigFile;
        if (raw.format === 'rgstudio-server-config-v2' && raw.encrypted_secrets) {
          decryptJsonWithKey<InfraSecrets>(raw.encrypted_secrets, key, CONFIG_AAD);
          writeReadDecryptOk = true;
        }
      } catch {
        writeReadDecryptOk = false;
      }
    }

    const survivedRestart = cfg.verified_restarts_count > 0;
    const effectiveDurability = envSecretsActive
      ? 'env-managed'
      : dirInfo.durability;

    // Never claim persistence_verified until encrypted write/read/decrypt AND a real process restart are both confirmed
    const persistenceVerified = writeReadDecryptOk && survivedRestart;

    let warning = dirInfo.warning;
    if (keySource === 'local-keyfile-fallback' && !envSecretsActive) {
      warning =
        'RG_CONFIG_ENCRYPTION_KEY environment secret is not set. Using a separate local master keyfile (.rgstudio-master.key) outside the encrypted config. Set RG_CONFIG_ENCRYPTION_KEY in Render/Railway Secrets for production hosting.' +
        (dirInfo.durability === 'ephemeral-container'
          ? ' AI Studio preview storage can reset on container rebuild — export an Encrypted Backup (.rgcfg) after saving.'
          : '');
    } else if (envSecretsActive) {
      warning = null;
    }

    return {
      write_read_decrypt_ok: writeReadDecryptOk,
      survived_process_restart: survivedRestart,
      persistence_verified: persistenceVerified,
      verified_restarts_count: cfg.verified_restarts_count,
      persistence_verified_at: cfg.persistence_verified_at,
      storage_durability: effectiveDurability,
      storage_location_label: envSecretsActive
        ? 'Platform-managed environment secrets + encrypted store'
        : dirInfo.label,
      key_source: keySource,
      env_secrets_active: envSecretsActive,
      warning,
    };
  }

  public verifyPersistentStorage(): PersistenceVerificationResult {
    const { key, encPath } = this.getPaths();
    const cfg = this.readConfig();

    // Perform a real write -> fsync -> re-read -> AES-256-GCM decrypt check without altering secrets
    if (!fs.existsSync(encPath)) {
      this.saveConfig({}, {}, { markSavedNow: true });
    }
    const raw = JSON.parse(fs.readFileSync(encPath, 'utf-8')) as PersistedConfigFile;
    if (raw.encrypted_secrets) {
      decryptJsonWithKey<InfraSecrets>(raw.encrypted_secrets, key, CONFIG_AAD);
    }

    // Also test writing and syncing a tiny probe file in the same directory
    const probeFile = `${encPath}.verify`;
    const fd = fs.openSync(probeFile, 'w', 0o600);
    try {
      fs.writeSync(fd, `verify:${CURRENT_BOOT_ID}`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    const readBack = fs.readFileSync(probeFile, 'utf-8');
    fs.unlinkSync(probeFile);
    if (readBack !== `verify:${CURRENT_BOOT_ID}`) {
      throw new Error('Storage read-back verification mismatch.');
    }

    if (cfg.saved_in_boot_id && cfg.saved_in_boot_id !== CURRENT_BOOT_ID && !cfg.persistence_verified) {
      this.markRestartVerified(raw);
    }

    return this.getPersistenceDetails();
  }

  private markRestartVerified(raw: PersistedConfigFile): void {
    const { encPath } = this.getPaths();
    raw.persistence_verified = true;
    raw.persistence_verified_at = new Date().toISOString();
    raw.verified_restarts_count = Number(raw.verified_restarts_count || 0) + 1;
    writeFileDurable(encPath, JSON.stringify(raw, null, 2));
  }

  public exportEncryptedBackup(passphrase: string): {
    filename: string;
    content: string;
  } {
    if (typeof passphrase !== 'string' || passphrase.length < 12) {
      throw new Error('Backup encryption passphrase must be at least 12 characters.');
    }
    const cfg = this.readConfig();
    const snapshot = {
      exported_at: new Date().toISOString(),
      app: 'RG Studio Management System',
      metadata: {
        supabase_host: cfg.supabase_host,
        supabase_port: cfg.supabase_port,
        supabase_user: cfg.supabase_user,
        supabase_db_name: cfg.supabase_db_name,
        db_ssl_require: cfg.db_ssl_require,
        db_pooler_mode: cfg.db_pooler_mode,
        fastapi_base_url: cfg.fastapi_base_url,
        cors_origins: cfg.cors_origins,
        sql_migration_confirmed: cfg.sql_migration_confirmed,
      },
      secrets: {
        supabase_password: cfg.supabase_password,
        jwt_secret_key: cfg.jwt_secret_key,
        jwt_refresh_secret_key: cfg.jwt_refresh_secret_key,
        setup_bootstrap_token: cfg.setup_bootstrap_token,
        sandbox_jwt_secret: cfg.sandbox_jwt_secret,
      },
    };

    const salt = crypto.randomBytes(16);
    const derivedKey = crypto.scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
    const encrypted = encryptJsonWithKey(snapshot, derivedKey, BACKUP_AAD);
    const checksum = crypto
      .createHash('sha256')
      .update(`${encrypted.iv}:${encrypted.tag}:${encrypted.ciphertext}`)
      .digest('hex');

    const bundle = {
      format: 'rgstudio-encrypted-config-v1',
      kdf: 'scrypt',
      salt: salt.toString('base64'),
      encrypted,
      sha256: checksum,
    };

    return {
      filename: `rgstudio-config-backup-${new Date().toISOString().slice(0, 10)}.rgcfg`,
      content: JSON.stringify(bundle, null, 2),
    };
  }

  public restoreEncryptedBackup(rawBackup: string, passphrase: string): DecryptedInfraConfig {
    if (!passphrase) {
      throw new Error('Backup decryption passphrase is required.');
    }
    let parsed: {
      format?: string;
      salt?: string;
      encrypted?: EncryptedEnvelope;
      sha256?: string;
    };
    try {
      parsed = JSON.parse(rawBackup);
    } catch {
      throw new Error('Invalid backup file format (expected JSON .rgcfg file).');
    }
    if (
      parsed.format !== 'rgstudio-encrypted-config-v1' ||
      !parsed.salt ||
      !parsed.encrypted ||
      !parsed.sha256
    ) {
      throw new Error('Unrecognized RG Studio encrypted backup structure.');
    }

    const expectedHash = crypto
      .createHash('sha256')
      .update(
        `${parsed.encrypted.iv}:${parsed.encrypted.tag}:${parsed.encrypted.ciphertext}`
      )
      .digest('hex');
    if (expectedHash !== parsed.sha256) {
      throw new Error('Backup checksum verification failed (file may be corrupted or modified).');
    }

    const salt = Buffer.from(parsed.salt, 'base64');
    const derivedKey = crypto.scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
    let snapshot: { metadata?: Partial<InfraMetadata>; secrets?: Partial<InfraSecrets> };
    try {
      snapshot = decryptJsonWithKey(parsed.encrypted, derivedKey, BACKUP_AAD);
    } catch {
      throw new Error('Unable to decrypt backup: wrong passphrase or corrupted envelope.');
    }

    return this.saveConfig(snapshot.metadata || {}, snapshot.secrets || {}, {
      markSavedNow: true,
    });
  }

  private sanitizeDbError(err: unknown, password?: string): string {
    let msg = err instanceof Error ? err.message : 'Database connection error.';
    if (password && password.length > 0) {
      msg = msg.split(password).join('••••••');
    }
    return msg;
  }

  public async testPostgresConnection(
    cfg: DecryptedInfraConfig
  ): Promise<{ ok: boolean; message: string }> {
    if (!cfg.supabase_host || !cfg.supabase_password) {
      return {
        ok: false,
        message: 'Enter and save your NEW Supabase hostname and database password first.',
      };
    }

    const client = new PgClient({
      host: cfg.supabase_host,
      port: cfg.supabase_port,
      user: cfg.supabase_user || 'postgres',
      database: cfg.supabase_db_name || 'postgres',
      password: cfg.supabase_password,
      ssl: cfg.db_ssl_require ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 6000,
      statement_timeout: 6000,
    });

    try {
      await client.connect();
      const res = await client.query<{
        pg_version: string;
        db_name: string;
        db_user: string;
      }>(
        'SELECT current_setting(\'server_version\') AS pg_version, current_database() AS db_name, current_user AS db_user'
      );
      const row = res.rows[0];
      return {
        ok: true,
        message: `Connected & authenticated to NEW Supabase PostgreSQL ${
          row?.pg_version || ''
        } (db=${row?.db_name || cfg.supabase_db_name}, user=${
          row?.db_user || cfg.supabase_user
        }, SSL=${cfg.db_ssl_require ? 'verified' : 'off'}). Ready for SQL migration.`,
      };
    } catch (err) {
      return {
        ok: false,
        message: `Pre-migration PostgreSQL connection failed: ${this.sanitizeDbError(
          err,
          cfg.supabase_password
        )}`,
      };
    } finally {
      await client.end().catch(() => {});
    }
  }

  public async verifyRequiredTables(cfg: DecryptedInfraConfig): Promise<{
    ok: boolean;
    found_count: number;
    required_count: number;
    found_tables: string[];
    missing_tables: string[];
    message: string;
  }> {
    if (!cfg.supabase_host || !cfg.supabase_password) {
      return {
        ok: false,
        found_count: 0,
        required_count: REQUIRED_TABLES_20.length,
        found_tables: [],
        missing_tables: [...REQUIRED_TABLES_20],
        message: 'Save and test your NEW Supabase project connection before verifying tables.',
      };
    }

    const client = new PgClient({
      host: cfg.supabase_host,
      port: cfg.supabase_port,
      user: cfg.supabase_user || 'postgres',
      database: cfg.supabase_db_name || 'postgres',
      password: cfg.supabase_password,
      ssl: cfg.db_ssl_require ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 6000,
      statement_timeout: 6000,
    });

    try {
      await client.connect();
      const res = await client.query<{ table_name: string }>(
        `SELECT table_name
         FROM information_schema.tables
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
         ORDER BY table_name`
      );
      const existing = new Set(res.rows.map((r) => r.table_name));
      const foundTables = REQUIRED_TABLES_20.filter((t) => existing.has(t));
      const missingTables = REQUIRED_TABLES_20.filter((t) => !existing.has(t));
      const ok = missingTables.length === 0;

      return {
        ok,
        found_count: foundTables.length,
        required_count: REQUIRED_TABLES_20.length,
        found_tables: [...foundTables],
        missing_tables: [...missingTables],
        message: ok
          ? `All 20/20 required RG Studio tables verified in NEW Supabase project (${cfg.supabase_db_name}). Database setup is complete.`
          : `Found ${foundTables.length}/20 required tables in NEW Supabase project. Missing ${missingTables.length} table(s): ${missingTables.join(', ')}. Run the copied SQL schema in Supabase SQL Editor first.`,
      };
    } catch (err) {
      return {
        ok: false,
        found_count: 0,
        required_count: REQUIRED_TABLES_20.length,
        found_tables: [],
        missing_tables: [...REQUIRED_TABLES_20],
        message: `Table verification query failed: ${this.sanitizeDbError(
          err,
          cfg.supabase_password
        )}`,
      };
    } finally {
      await client.end().catch(() => {});
    }
  }

  public async probePostgresTls(
    host: string,
    port: number
  ): Promise<{ ok: boolean; message: string }> {
    return new Promise((resolve) => {
      const socket = net.createConnection({ host, port });
      let settled = false;
      const done = (ok: boolean, message: string) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve({ ok, message });
      };

      socket.setTimeout(5000);
      socket.on('timeout', () => done(false, `Timed out connecting to ${host}:${port} after 5s.`));
      socket.on('error', (err) => done(false, `Connection error: ${err.message}`));

      socket.on('connect', () => {
        const sslReq = Buffer.alloc(8);
        sslReq.writeInt32BE(8, 0);
        sslReq.writeInt32BE(80877103, 4);
        socket.write(sslReq);
      });

      socket.once('data', (chunk) => {
        if (chunk.length === 1 && chunk[0] === 0x53) {
          const tlsSock = tls.connect({ socket, servername: host, rejectUnauthorized: true }, () => {
            const proto = tlsSock.getProtocol() || 'TLS';
            tlsSock.end();
            done(true, `Supabase PostgreSQL host reachable and ${proto} certificate verified.`);
          });
          tlsSock.on('error', (err) => done(false, `TLS handshake failed: ${err.message}`));
        } else {
          done(false, 'Host responded, but refused PostgreSQL SSL/TLS upgrade.');
        }
      });
    });
  }

  public async testFastApiHealth(url: string): Promise<{ ok: boolean; message: string }> {
    if (!url) {
      return { ok: false, message: 'FastAPI backend URL is not configured yet.' };
    }
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(`${url}/api/v1/health`, { signal: controller.signal });
      clearTimeout(timeout);
      const data = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
      const healthy = resp.ok && data.status === 'online' && data.database === 'connected';
      return {
        ok: healthy,
        message: healthy
          ? `FastAPI online and database connected (${String(data.environment || 'production')}).`
          : `HTTP ${resp.status}: ${JSON.stringify(data)}`,
      };
    } catch (err) {
      return {
        ok: false,
        message: `Unable to reach FastAPI backend: ${
          err instanceof Error ? err.message : 'network error'
        }`,
      };
    }
  }

  public initBootRestoreSync(): void {
    this.migrateLegacyIfNeeded();
    const { key, encPath } = this.getPaths();

    if (fs.existsSync(encPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(encPath, 'utf-8')) as PersistedConfigFile;
        if (raw.encrypted_secrets) {
          decryptJsonWithKey<InfraSecrets>(raw.encrypted_secrets, key, CONFIG_AAD);
        }
        if (
          !this.bootVerifiedCounted &&
          raw.saved_in_boot_id &&
          raw.saved_in_boot_id !== CURRENT_BOOT_ID
        ) {
          this.bootVerifiedCounted = true;
          this.markRestartVerified(raw);
        }
      } catch {
        // Handled cleanly in persistence details
      }
    }

    const cfg = this.readConfig();
    const dbConfigured = Boolean(cfg.supabase_host && cfg.supabase_password);
    const jwtConfigured = Boolean(cfg.jwt_secret_key && cfg.jwt_refresh_secret_key);
    const apiConfigured = Boolean(cfg.fastapi_base_url);

    this.lastStartupRestore = {
      restored_at: new Date().toISOString(),
      boot_id_short: CURRENT_BOOT_ID.slice(0, 8),
      overall_status:
        dbConfigured && jwtConfigured && apiConfigured
          ? cfg.last_db_test_ok && cfg.last_backend_test_ok
            ? 'Online'
            : 'Offline'
          : 'Configuration Required',
      fastapi_status: apiConfigured
        ? cfg.last_backend_test_ok
          ? 'Online'
          : 'Offline'
        : 'Not Configured',
      database_status: cfg.supabase_host
        ? cfg.last_db_test_ok
          ? 'Connected'
          : 'Disconnected'
        : 'Not Configured',
      message:
        dbConfigured || jwtConfigured || apiConfigured
          ? 'Permanent encrypted configuration restored at startup.'
          : 'No permanent infrastructure configuration saved yet.',
    };
  }

  public async runStartupRestore(): Promise<StartupRestoreState> {
    this.initBootRestoreSync();

    let cfg = this.readConfig();
    const dbConfigured = Boolean(cfg.supabase_host && cfg.supabase_password);
    const jwtConfigured = Boolean(cfg.jwt_secret_key && cfg.jwt_refresh_secret_key);
    const apiConfigured = Boolean(cfg.fastapi_base_url);

    let dbStatus: 'Connected' | 'Disconnected' | 'Not Configured' = 'Not Configured';
    let apiStatus: 'Online' | 'Offline' | 'Not Configured' = 'Not Configured';

    if (cfg.supabase_host) {
      const dbProbe = cfg.supabase_password
        ? await this.testPostgresConnection(cfg)
        : await this.probePostgresTls(cfg.supabase_host, cfg.supabase_port);
      dbStatus = dbProbe.ok ? 'Connected' : 'Disconnected';
      cfg = this.saveConfig(
        {
          last_db_test_ok: dbProbe.ok,
          last_db_test_message: dbProbe.message,
          last_db_test_at: new Date().toISOString(),
        },
        undefined,
        { markSavedNow: false, preserveVerification: true }
      );
    }

    if (apiConfigured) {
      const apiProbe = await this.testFastApiHealth(cfg.fastapi_base_url);
      apiStatus = apiProbe.ok ? 'Online' : 'Offline';
      cfg = this.saveConfig(
        {
          last_backend_test_ok: apiProbe.ok,
          last_backend_test_message: apiProbe.message,
          last_backend_test_at: new Date().toISOString(),
        },
        undefined,
        { markSavedNow: false, preserveVerification: true }
      );
    }

    let overallStatus: 'Online' | 'Offline' | 'Configuration Required' = 'Configuration Required';
    let message = 'Supabase database, JWT secrets, or FastAPI URL still require setup.';

    if (dbConfigured && jwtConfigured && apiConfigured) {
      if (dbStatus === 'Connected' && apiStatus === 'Online') {
        overallStatus = 'Online';
        message = 'Saved configuration restored automatically; Supabase TLS and FastAPI are Online.';
      } else {
        overallStatus = 'Offline';
        message =
          'Saved configuration restored automatically and preserved, but Supabase or FastAPI is currently unreachable.';
      }
    } else if (dbConfigured || jwtConfigured || apiConfigured) {
      overallStatus = 'Configuration Required';
      message = 'Partial permanent configuration restored; complete remaining setup steps.';
    }

    this.lastStartupRestore = {
      restored_at: new Date().toISOString(),
      boot_id_short: CURRENT_BOOT_ID.slice(0, 8),
      overall_status: overallStatus,
      fastapi_status: apiStatus,
      database_status: dbStatus,
      message,
    };
    return this.lastStartupRestore;
  }

  public getStartupRestoreState(): StartupRestoreState {
    return this.lastStartupRestore;
  }

  public getOrCreateSandboxJwtSecret(): string {
    const envSandboxSecret = String(process.env.RG_SANDBOX_JWT_SECRET || '').trim();
    if (envSandboxSecret.length >= 32) {
      return envSandboxSecret;
    }
    const cfg = this.readConfig();
    if (cfg.sandbox_jwt_secret && cfg.sandbox_jwt_secret.length >= 32) {
      return cfg.sandbox_jwt_secret;
    }
    const generated = crypto.randomBytes(32).toString('hex');
    this.saveConfig({}, { sandbox_jwt_secret: generated }, { markSavedNow: false, preserveVerification: true });
    return generated;
  }

  private computeSecretHashes(secrets: InfraSecrets): Record<string, string> {
    const hashes: Record<string, string> = {};
    const keys: (keyof InfraSecrets)[] = [
      'supabase_password',
      'jwt_secret_key',
      'jwt_refresh_secret_key',
      'setup_bootstrap_token',
      'sandbox_jwt_secret',
    ];
    for (const field of keys) {
      const val = secrets[field] || '';
      hashes[field] = crypto.createHash('sha256').update(val, 'utf-8').digest('hex');
    }
    return hashes;
  }

  public getKeyMigrationStatus(): KeyMigrationStatus {
    const { keyFingerprint, keySource, hostingEnvSynced, encPath, stagePath, preBackupPath } =
      this.getPaths();
    const raw = this.readRawConfigFile(encPath);

    let staged: KeyMigrationStatus['staged'] = null;
    if (fs.existsSync(stagePath)) {
      try {
        const s = JSON.parse(fs.readFileSync(stagePath, 'utf-8')) as StagedKeyMigrationFile;
        if (s.format === 'rgstudio-key-migration-stage-v1') {
          staged = {
            staged_at: s.staged_at,
            initiated_by: s.initiated_by,
            old_key_fingerprint: s.old_key_fingerprint,
            new_key_fingerprint: s.new_key_fingerprint,
            migrated_secret_fields: s.migrated_secret_fields,
            decryption_verified: Boolean(s.decryption_verified),
            verified_at: s.verified_at,
            pre_migration_backup_created: fs.existsSync(s.pre_migration_backup_path),
            pre_migration_backup_sha256: s.pre_migration_backup_sha256,
          };
        }
      } catch {
        staged = null;
      }
    }

    const lastMigration = raw?.last_migration ?? null;
    const migrationState: KeyMigrationStatus['migration_state'] = staged?.decryption_verified
      ? 'staged_verified'
      : lastMigration
        ? 'activated'
        : 'idle';

    const envSet = Boolean(String(process.env.RG_CONFIG_ENCRYPTION_KEY || '').trim());
    let hostingEnvNotice: string | null = null;
    if (envSet && !hostingEnvSynced) {
      hostingEnvNotice =
        'Hosting environment variable RG_CONFIG_ENCRYPTION_KEY differs from the newly activated server key. The server safely persists the active migrated key in protected server storage (.rgstudio-master.key / .rgstudio-hosting-secrets.env); set a new key in your hosting Secret Manager if redeploying to a fresh container without persistent disk.';
    }

    return {
      active_key_fingerprint: raw?.master_key_fingerprint || keyFingerprint,
      key_source: keySource,
      hosting_env_synced: hostingEnvSynced,
      hosting_env_notice: hostingEnvNotice,
      migration_state: migrationState,
      has_pre_migration_backup: fs.existsSync(preBackupPath),
      staged,
      last_migration: lastMigration,
    };
  }

  public prepareKeyMigration(params: {
    backupPassphrase: string;
    initiatedBy: string;
    customNewKey?: string;
  }): KeyMigrationStatus {
    const { backupPassphrase, initiatedBy, customNewKey } = params;
    if (typeof backupPassphrase !== 'string' || backupPassphrase.length < 12) {
      throw new Error('A backup encryption passphrase of at least 12 characters is required before staging key migration.');
    }

    // Ensure sandbox_jwt_secret exists and current encrypted config decrypts cleanly under active OLD key
    this.getOrCreateSandboxJwtSecret();
    const { key: oldKey, keyFingerprint: oldFingerprint, encPath, stagePath, preBackupPath } =
      this.getPaths();

    if (!fs.existsSync(encPath)) {
      this.saveConfig({}, {}, { markSavedNow: false, preserveVerification: true });
    }

    const currentRaw = this.readRawConfigFile(encPath);
    if (!currentRaw) {
      throw new Error('Unable to read encrypted configuration store.');
    }

    // Decrypt existing secrets using current OLD key (verify old key still works and is untouched)
    const cfg = this.readConfig();
    const existingSecrets: InfraSecrets = {
      supabase_password: cfg.supabase_password,
      jwt_secret_key: cfg.jwt_secret_key,
      jwt_refresh_secret_key: cfg.jwt_refresh_secret_key,
      setup_bootstrap_token: cfg.setup_bootstrap_token,
      sandbox_jwt_secret: cfg.sandbox_jwt_secret,
    };

    if (currentRaw.encrypted_secrets) {
      const decryptedDirect = decryptJsonWithKey<Partial<InfraSecrets>>(
        currentRaw.encrypted_secrets,
        oldKey,
        CONFIG_AAD
      );
      if (typeof decryptedDirect !== 'object' || decryptedDirect === null) {
        throw new Error('Existing encrypted secrets failed decryption verification.');
      }
    }

    // Step 1: Preserve a recoverable AES-256-GCM encrypted backup BEFORE staging rotation
    const backup = this.exportEncryptedBackup(backupPassphrase);
    const parsedBackup = JSON.parse(backup.content) as { sha256: string };
    writeFileDurable(preBackupPath, backup.content);

    // Step 2: Generate a new cryptographically secure 256-bit key (never returned in API responses)
    let newKeyBuf: Buffer;
    let newKeyHex: string;
    const trimmedCustom = String(customNewKey || '').trim();
    if (trimmedCustom) {
      if (trimmedCustom.length < 32) {
        throw new Error('Provided RG_CONFIG_ENCRYPTION_KEY must be at least 32 characters (256-bit recommended).');
      }
      if (/^[a-fA-F0-9]{64}$/.test(trimmedCustom)) {
        newKeyHex = trimmedCustom.toLowerCase();
        newKeyBuf = Buffer.from(newKeyHex, 'hex');
      } else {
        newKeyBuf = Buffer.from(
          crypto.hkdfSync(
            'sha256',
            Buffer.from(trimmedCustom, 'utf-8'),
            Buffer.from('rgstudio-config-salt-v1', 'utf-8'),
            Buffer.from('aes-256-gcm-master', 'utf-8'),
            32
          )
        );
        newKeyHex = newKeyBuf.toString('hex');
      }
    } else {
      newKeyBuf = crypto.randomBytes(32);
      newKeyHex = newKeyBuf.toString('hex');
    }

    const newFingerprint = computeKeyFingerprint(newKeyBuf);
    if (newFingerprint === oldFingerprint) {
      throw new Error('New encryption key must differ from the active encryption key.');
    }

    // Step 3: Re-encrypt ALL secrets using the NEW 256-bit key (old key & live config remain untouched)
    const stagedEnvelope = encryptJsonWithKey(existingSecrets, newKeyBuf, CONFIG_AAD);
    const originalHashes = this.computeSecretHashes(existingSecrets);

    // Step 4: Verify staged values decrypt cleanly under the NEW key with byte-for-byte hash parity
    const verifiedPlain = decryptJsonWithKey<InfraSecrets>(stagedEnvelope, newKeyBuf, CONFIG_AAD);
    const verifiedHashes = this.computeSecretHashes(verifiedPlain);
    for (const [k, digest] of Object.entries(originalHashes)) {
      if (verifiedHashes[k] !== digest) {
        throw new Error(`Migrated secret integrity check failed for '${k}'. Old key was preserved untouched.`);
      }
    }

    const populatedFields = (Object.keys(existingSecrets) as (keyof InfraSecrets)[]).filter(
      (k) => Boolean(existingSecrets[k])
    );

    const stagePayload: StagedKeyMigrationFile = {
      format: 'rgstudio-key-migration-stage-v1',
      staged_at: new Date().toISOString(),
      initiated_by: initiatedBy,
      old_key_fingerprint: oldFingerprint,
      new_key_fingerprint: newFingerprint,
      new_key_hex: newKeyHex,
      pre_migration_backup_path: preBackupPath,
      pre_migration_backup_sha256: parsedBackup.sha256,
      migrated_secret_fields: populatedFields,
      staged_envelope: stagedEnvelope,
      decryption_verified: true,
      verified_at: new Date().toISOString(),
      secret_hashes: originalHashes,
    };

    writeFileDurable(stagePath, JSON.stringify(stagePayload, null, 2));
    return this.getKeyMigrationStatus();
  }

  public activateKeyMigration(params: {
    confirmationPhrase: string;
    initiatedBy: string;
  }): KeyMigrationStatus {
    const { confirmationPhrase, initiatedBy } = params;
    if (confirmationPhrase.trim() !== 'CONFIRM KEY ROTATION') {
      throw new Error('Explicit administrator confirmation is required: type CONFIRM KEY ROTATION.');
    }

    const {
      key: oldKey,
      encPath,
      stagePath,
      preBackupPath,
      masterKeyPath,
      prevMasterKeyPath,
      hostingSecretsPath,
    } = this.getPaths();

    if (!fs.existsSync(stagePath)) {
      throw new Error('No staged key migration found. Prepare & verify key migration first.');
    }
    if (!fs.existsSync(preBackupPath)) {
      throw new Error('Pre-migration encrypted backup is missing. Re-run Step 1 to create a recoverable backup first.');
    }

    const stage = JSON.parse(fs.readFileSync(stagePath, 'utf-8')) as StagedKeyMigrationFile;
    if (stage.format !== 'rgstudio-key-migration-stage-v1' || !stage.decryption_verified) {
      throw new Error('Staged key migration is not verified. Activation aborted; old key preserved.');
    }

    const currentRaw = this.readRawConfigFile(encPath);
    if (!currentRaw) {
      throw new Error('Active encrypted config file missing. Activation aborted.');
    }

    // Re-verify live config under old key matches staged secrets before switching keys
    const liveCfg = this.readConfig();
    const liveSecrets: InfraSecrets = {
      supabase_password: liveCfg.supabase_password,
      jwt_secret_key: liveCfg.jwt_secret_key,
      jwt_refresh_secret_key: liveCfg.jwt_refresh_secret_key,
      setup_bootstrap_token: liveCfg.setup_bootstrap_token,
      sandbox_jwt_secret: liveCfg.sandbox_jwt_secret,
    };
    const liveHashes = this.computeSecretHashes(liveSecrets);

    const newKeyBuf = Buffer.from(stage.new_key_hex, 'hex');
    const stagedDecrypted = decryptJsonWithKey<InfraSecrets>(stage.staged_envelope, newKeyBuf, CONFIG_AAD);
    const stagedHashes = this.computeSecretHashes(stagedDecrypted);

    for (const [k, digest] of Object.entries(liveHashes)) {
      if (stagedHashes[k] !== digest) {
        throw new Error(
          `Configuration secrets changed since staging ('${k}'). Cancel and re-stage key migration so no secrets are lost.`
        );
      }
    }

    // Archive existing key material (never discard before migration completes)
    if (fs.existsSync(masterKeyPath)) {
      writeFileDurable(prevMasterKeyPath, fs.readFileSync(masterKeyPath, 'utf-8'));
    } else {
      writeFileDurable(prevMasterKeyPath, `${oldKey.toString('hex')}\n`);
    }

    // Store NEW 256-bit key securely on server + update runtime process env + protected hosting secret file
    writeFileDurable(masterKeyPath, `${stage.new_key_hex}\n`);
    writeFileDurable(
      hostingSecretsPath,
      [
        '# RG STUDIO SERVER-ONLY HOSTING ENCRYPTION SECRET (DO NOT COMMIT OR EXPOSE)',
        `RG_CONFIG_ENCRYPTION_KEY=${stage.new_key_hex}`,
        `RG_CONFIG_ENCRYPTION_KEY_FINGERPRINT=${stage.new_key_fingerprint}`,
        `RG_CONFIG_ENCRYPTION_KEY_ROTATED_AT=${new Date().toISOString()}`,
        '',
      ].join('\n')
    );
    process.env.RG_CONFIG_ENCRYPTION_KEY_PREVIOUS = oldKey.toString('hex');
    process.env.RG_CONFIG_ENCRYPTION_KEY = stage.new_key_hex;

    const migrationRecord: KeyMigrationRecord = {
      activated_at: new Date().toISOString(),
      initiated_by: initiatedBy,
      old_key_fingerprint: stage.old_key_fingerprint,
      new_key_fingerprint: stage.new_key_fingerprint,
      migrated_secret_fields: stage.migrated_secret_fields,
      post_activation_verified: false,
      backup_preserved: fs.existsSync(preBackupPath),
    };

    const nextConfig: PersistedConfigFile = {
      ...currentRaw,
      master_key_fingerprint: stage.new_key_fingerprint,
      last_migration: migrationRecord,
      encrypted_secrets: encryptJsonWithKey(liveSecrets, newKeyBuf, CONFIG_AAD),
    };
    writeFileDurable(encPath, JSON.stringify(nextConfig, null, 2));

    // Post-activation verification: read & decrypt live config using newly activated key
    const verifiedAfter = this.readConfig();
    const afterSecrets: InfraSecrets = {
      supabase_password: verifiedAfter.supabase_password,
      jwt_secret_key: verifiedAfter.jwt_secret_key,
      jwt_refresh_secret_key: verifiedAfter.jwt_refresh_secret_key,
      setup_bootstrap_token: verifiedAfter.setup_bootstrap_token,
      sandbox_jwt_secret: verifiedAfter.sandbox_jwt_secret,
    };
    const afterHashes = this.computeSecretHashes(afterSecrets);
    for (const [k, digest] of Object.entries(liveHashes)) {
      if (afterHashes[k] !== digest) {
        throw new Error(`Post-activation verification failed for '${k}'. Use pre-migration backup to recover.`);
      }
    }

    migrationRecord.post_activation_verified = true;
    nextConfig.last_migration = migrationRecord;
    writeFileDurable(encPath, JSON.stringify(nextConfig, null, 2));

    // Clean up staging file after full activation + verification
    if (fs.existsSync(stagePath)) {
      fs.unlinkSync(stagePath);
    }

    return this.getKeyMigrationStatus();
  }

  public cancelKeyMigration(): KeyMigrationStatus {
    const { stagePath } = this.getPaths();
    if (fs.existsSync(stagePath)) {
      fs.unlinkSync(stagePath);
    }
    return this.getKeyMigrationStatus();
  }

  public getPreMigrationBackupFile(): { filename: string; content: string } {
    const { preBackupPath } = this.getPaths();
    if (!fs.existsSync(preBackupPath)) {
      throw new Error('No pre-migration encrypted backup file found on server.');
    }
    return {
      filename: `rgstudio-pre-key-migration-${new Date().toISOString().slice(0, 10)}.rgcfg`,
      content: fs.readFileSync(preBackupPath, 'utf-8'),
    };
  }
}
