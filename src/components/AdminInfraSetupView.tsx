import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Copy,
  Database,
  Download,
  ExternalLink,
  HardDrive,
  KeyRound,
  Lock,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  Table2,
  Upload,
} from 'lucide-react';
import { ConnectionState, UserSummary } from '../types/auth';

interface PersistenceDetails {
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

interface KeyMigrationStatus {
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
  last_migration: {
    activated_at: string;
    initiated_by: string;
    old_key_fingerprint: string;
    new_key_fingerprint: string;
    migrated_secret_fields: string[];
    post_activation_verified: boolean;
    backup_preserved: boolean;
  } | null;
}

interface StartupRestoreState {
  restored_at: string;
  boot_id_short: string;
  overall_status: 'Online' | 'Offline' | 'Configuration Required';
  fastapi_status: 'Online' | 'Offline' | 'Not Configured';
  database_status: 'Connected' | 'Disconnected' | 'Not Configured';
  message: string;
}

interface InfraStatus {
  has_database_config: boolean;
  masked_db_host: string;
  supabase_host: string;
  supabase_port: number;
  supabase_user: string;
  supabase_db_name: string;
  db_ssl_require: boolean;
  db_pooler_mode: boolean;
  db_project_label: string;
  is_new_supabase_project: boolean;
  has_jwt_secrets: boolean;
  has_bootstrap_token: boolean;
  fastapi_base_url: string;
  cors_origins: string;
  sql_migration_confirmed: boolean;
  tables_verified: boolean;
  database_setup_complete: boolean;
  required_tables: string[];
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
  last_saved_at: string | null;
  database_status: 'Connected' | 'Disconnected' | 'Not Configured';
  fastapi_status: 'Online' | 'Offline' | 'Not Configured';
  overall_status: 'Online' | 'Offline' | 'Configuration Required';
  persistence_verified: boolean;
  persistence_details: PersistenceDetails;
  startup_restore: StartupRestoreState;
  key_migration: KeyMigrationStatus;
  preserved_existing_secrets?: boolean;
  artifacts: {
    has_sql_migration: boolean;
    has_dockerfile: boolean;
    has_render_blueprint: boolean;
    has_procfile: boolean;
  };
  readiness: {
    admin_initialized: boolean;
    db_configured: boolean;
    db_tls_verified: boolean;
    sql_migration_confirmed: boolean;
    tables_verified: boolean;
    database_setup_complete: boolean;
    secrets_generated: boolean;
    fastapi_healthy: boolean;
    persistence_verified: boolean;
  };
}

interface AdminInfraSetupViewProps {
  token: string;
  currentUser: UserSummary;
  connectionState: ConnectionState;
}

export const AdminInfraSetupView: React.FC<AdminInfraSetupViewProps> = ({
  token,
  currentUser,
  connectionState,
}) => {
  const [status, setStatus] = useState<InfraStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [copiedSql, setCopiedSql] = useState(false);

  // Write-only form inputs (secrets cleared immediately after save/export)
  const [editingDb, setEditingDb] = useState(false);
  const [connectionUri, setConnectionUri] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('6543');
  const [dbUser, setDbUser] = useState('postgres');
  const [dbName, setDbName] = useState('postgres');
  const [dbPassword, setDbPassword] = useState('');
  const [sslRequire, setSslRequire] = useState(true);
  const [poolerMode, setPoolerMode] = useState(true);
  const [fastapiUrl, setFastapiUrl] = useState('');
  const [confirmRotateKeys, setConfirmRotateKeys] = useState(false);

  // Encrypted backup passphrase & restore upload state
  const [exportPassphrase, setExportPassphrase] = useState('');
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreBackupJson, setRestoreBackupJson] = useState('');
  const [restoreFileName, setRestoreFileName] = useState('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Safe RG_CONFIG_ENCRYPTION_KEY migration workflow state (never holds server-generated keys)
  const [migrationBackupPassphrase, setMigrationBackupPassphrase] = useState('');
  const [customNewKeyInput, setCustomNewKeyInput] = useState('');
  const [showCustomNewKey, setShowCustomNewKey] = useState(false);
  const [activationConfirmation, setActivationConfirmation] = useState('');

  const applyLoadedStatus = useCallback((data: InfraStatus) => {
    setStatus(data);
    setHost(data.supabase_host || '');
    setPort(String(data.supabase_port || 6543));
    setDbUser(data.supabase_user || 'postgres');
    setDbName(data.supabase_db_name || 'postgres');
    setSslRequire(Boolean(data.db_ssl_require));
    setPoolerMode(Boolean(data.db_pooler_mode));
    setFastapiUrl(data.fastapi_base_url || '');
    setEditingDb(!data.has_database_config);
  }, []);

  const loadStatus = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/admin/infra/status', {
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to load infrastructure settings.');
        return;
      }
      applyLoadedStatus(data);
    } catch {
      setError('Failed to reach server configuration endpoint.');
    } finally {
      setLoading(false);
    }
  }, [token, applyLoadedStatus]);

  useEffect(() => {
    if (currentUser.role_code === 'admin') {
      loadStatus();
    } else {
      setLoading(false);
    }
  }, [currentUser.role_code, loadStatus]);

  if (currentUser.role_code !== 'admin') {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 text-sm text-red-600 dark:text-red-400">
        Administrator access is required to view or modify permanent infrastructure settings.
      </div>
    );
  }

  const requireOnline = (): boolean => {
    if (connectionState === 'Offline') {
      setError('Client is Offline. Switch back to Online before modifying server configuration.');
      return false;
    }
    return true;
  };

  const handleResetDatabaseTarget = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('reset_db');
    try {
      const res = await fetch('/api/v1/admin/infra/database/reset-target', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to reset database target.');
        return;
      }
      applyLoadedStatus(data);
      setConnectionUri('');
      setDbPassword('');
      setEditingDb(true);
      setNotice(
        'Old Supabase connection target cleared for your NEW Supabase project. Admin account, RBAC, JWT secrets, RG_CONFIG_ENCRYPTION_KEY, and FastAPI URL were preserved.'
      );
    } catch {
      setError('Network error resetting database target.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleSaveDatabase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('save_db');
    try {
      const res = await fetch('/api/v1/admin/infra/database', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          connection_uri: connectionUri.trim() || undefined,
          supabase_host: host.trim(),
          supabase_port: Number(port) || 6543,
          supabase_user: dbUser.trim(),
          supabase_db_name: dbName.trim(),
          supabase_password: dbPassword || undefined,
          db_ssl_require: sslRequire,
          db_pooler_mode: poolerMode,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to save NEW Supabase database configuration.');
        return;
      }
      applyLoadedStatus(data);
      setConnectionUri('');
      setDbPassword('');
      setEditingDb(false);
      setNotice(
        'NEW Supabase Project credentials encrypted (AES-256-GCM) and saved on the server. Existing JWT secrets and RG_CONFIG_ENCRYPTION_KEY were preserved. Next: click "Test NEW Supabase Connection (Pre-Migration)".'
      );
    } catch {
      setError('Network error saving database configuration.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleTestDbConnection = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('test_db');
    try {
      const res = await fetch('/api/v1/admin/infra/test-db', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Pre-migration connection test failed.');
        return;
      }
      applyLoadedStatus(data);
      if (data.last_db_test_ok) {
        setNotice(
          'Pre-migration connection test passed! Next: Copy the 20-table schema SQL below, run it in your NEW Supabase SQL Editor, then click "Verify All 20 Required Tables".'
        );
      } else {
        setError(data.last_db_test_message || 'Pre-migration connection failed.');
      }
    } catch {
      setError('Unable to run server database connection check.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleCopySql = async () => {
    setError(null);
    setNotice(null);
    setBusyAction('copy_sql');
    try {
      const res = await fetch('/api/v1/admin/infra/migration-sql', {
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Could not load SQL migration.');
        return;
      }
      await navigator.clipboard.writeText(data.sql);
      setCopiedSql(true);
      setNotice(
        'Copied all 20-table SQL schema commands to clipboard. Open your NEW Supabase project -> SQL Editor -> New query -> Paste -> Click Run, then return here and click "Verify All 20 Required Tables".'
      );
      window.setTimeout(() => setCopiedSql(false), 4000);
    } catch {
      setError('Unable to copy SQL to clipboard. Check browser clipboard permissions.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleVerifyTables = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('verify_tables');
    try {
      const res = await fetch('/api/v1/admin/infra/verify-tables', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to verify 20 required tables.');
        return;
      }
      applyLoadedStatus(data);
      if (data.tables_verified) {
        setNotice(
          'All 20/20 required RG Studio tables verified in your NEW Supabase project! Database setup is now complete.'
        );
      } else {
        setError(
          data.last_table_verify_message ||
            'Not all 20 tables were found yet. Run the copied schema SQL in Supabase SQL Editor first.'
        );
      }
    } catch {
      setError('Unable to query NEW Supabase tables.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleGenerateSecrets = async (forceRegenerate = false) => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('gen_secrets');
    try {
      const res = await fetch('/api/v1/admin/infra/generate-secrets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({ force_regenerate: forceRegenerate }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to configure security secrets.');
        return;
      }
      applyLoadedStatus(data);
      setConfirmRotateKeys(false);
      setNotice(
        data.preserved_existing_secrets
          ? 'Existing working JWT security keys were preserved and not overwritten.'
          : forceRegenerate
            ? 'JWT signing secrets rotated and encrypted securely on the server.'
            : 'JWT signing secrets and bootstrap token encrypted and saved securely on the server.'
      );
    } catch {
      setError('Error configuring server secrets.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleDownloadEnv = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('download_env');
    try {
      const res = await fetch('/api/v1/admin/infra/download-env', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || 'Unable to generate environment file.');
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'rgstudio-backend-template.env';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setNotice(
        'Downloaded rgstudio-backend-template.env (secrets safely redacted — fill password, JWT keys, and RG_CONFIG_ENCRYPTION_KEY directly inside your hosting Secret Manager).'
      );
    } catch {
      setError('Unable to download server environment file.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleSaveDeployment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('save_deploy');
    try {
      const res = await fetch('/api/v1/admin/infra/deployment', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          fastapi_base_url: fastapiUrl.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to save backend URL.');
        return;
      }
      applyLoadedStatus(data);
      setNotice('FastAPI Backend URL saved permanently and will restore automatically on startup.');
    } catch {
      setError('Error saving backend URL.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleTestBackend = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('test_backend');
    try {
      const res = await fetch('/api/v1/admin/infra/test-backend', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Backend check failed.');
        return;
      }
      applyLoadedStatus(data);
    } catch {
      setError('Error checking FastAPI backend health.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleVerifyPersistence = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('verify_persistence');
    try {
      const res = await fetch('/api/v1/admin/infra/verify-persistence', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Persistence verification failed.');
        return;
      }
      applyLoadedStatus(data);
      if (data.persistence_verified) {
        setNotice(
          `Persistent storage verified across ${data.persistence_details.verified_restarts_count} backend restart(s).`
        );
      } else {
        setNotice(
          'Disk write/AES-256-GCM decrypt check succeeded. Restart the backend process once to complete cross-restart persistence verification.'
        );
      }
    } catch {
      setError('Unable to verify persistent storage.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleExportBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('export_backup');
    try {
      const res = await fetch('/api/v1/admin/infra/backup/export', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({ passphrase: exportPassphrase }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || 'Unable to export encrypted backup.');
        return;
      }
      const disposition = res.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="([^"]+)"/);
      const filename = match ? match[1] : 'rgstudio-config-backup.rgcfg';
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setExportPassphrase('');
      setNotice(`Encrypted configuration backup (${filename}) downloaded. Keep your passphrase safe.`);
    } catch {
      setError('Unable to export encrypted configuration backup.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleBackupFileSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setRestoreBackupJson(text);
    setRestoreFileName(file.name);
  };

  const handleRestoreBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireOnline()) return;
    if (!restoreBackupJson) {
      setError('Choose a .rgcfg encrypted backup file first.');
      return;
    }
    setError(null);
    setNotice(null);
    setBusyAction('restore_backup');
    try {
      const res = await fetch('/api/v1/admin/infra/backup/restore', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          backup_json: restoreBackupJson,
          passphrase: restorePassphrase,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to restore encrypted backup.');
        return;
      }
      applyLoadedStatus(data);
      setRestorePassphrase('');
      setRestoreBackupJson('');
      setRestoreFileName('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      setNotice('Configuration backup decrypted, restored permanently, and validated.');
    } catch {
      setError('Unable to restore configuration backup.');
    } finally {
      setBusyAction(null);
    }
  };

  const handlePrepareKeyMigration = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('key_mig_prepare');
    try {
      const res = await fetch('/api/v1/admin/infra/key-migration/prepare', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          backup_passphrase: migrationBackupPassphrase,
          custom_new_key: showCustomNewKey && customNewKeyInput.trim() ? customNewKeyInput.trim() : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to stage encryption key migration.');
        return;
      }
      applyLoadedStatus(data);
      setMigrationBackupPassphrase('');
      setCustomNewKeyInput('');
      setShowCustomNewKey(false);
      setActivationConfirmation('');
      setNotice(
        'New 256-bit RG_CONFIG_ENCRYPTION_KEY generated on server, pre-migration .rgcfg backup created, and all migrated secrets verified via decryption. Old key stays active until you confirm activation.'
      );
    } catch {
      setError('Network error preparing encryption key migration.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleDownloadPreMigrationBackup = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('key_mig_backup');
    try {
      const res = await fetch('/api/v1/admin/infra/key-migration/download-backup', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || 'Unable to download pre-migration backup.');
        return;
      }
      const disposition = res.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="([^"]+)"/);
      const filename = match ? match[1] : 'rgstudio-pre-key-migration.rgcfg';
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setNotice(`Downloaded recoverable encrypted backup (${filename}).`);
    } catch {
      setError('Unable to download pre-migration encrypted backup.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleActivateKeyMigration = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('key_mig_activate');
    try {
      const res = await fetch('/api/v1/admin/infra/key-migration/activate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify({ confirmation_phrase: activationConfirmation }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to activate new encryption key.');
        return;
      }
      applyLoadedStatus(data);
      setActivationConfirmation('');
      setNotice(
        'New 256-bit RG_CONFIG_ENCRYPTION_KEY activated and post-activation decryption verified! Existing Admin/Employee accounts, RBAC, and JWT secrets were preserved.'
      );
    } catch {
      setError('Network error activating new encryption key.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleCancelKeyMigration = async () => {
    if (!requireOnline()) return;
    setError(null);
    setNotice(null);
    setBusyAction('key_mig_cancel');
    try {
      const res = await fetch('/api/v1/admin/infra/key-migration/cancel', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || 'Unable to cancel staged migration.');
        return;
      }
      applyLoadedStatus(data);
      setActivationConfirmation('');
      setNotice('Staged key migration cancelled. Your existing encryption key remains unchanged.');
    } catch {
      setError('Unable to cancel staged key migration.');
    } finally {
      setBusyAction(null);
    }
  };

  if (loading || !status) {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 text-sm text-slate-500">
        Loading permanent infrastructure settings...
      </div>
    );
  }

  const pDetails = status.persistence_details;
  const km = status.key_migration;
  const verifiedSet = new Set(status.verified_tables_list || []);
  const requiredTables = status.required_tables || [];

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Infrastructure Settings Dashboard Status Grid */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-lg font-semibold tracking-tight">
                Infrastructure Settings &amp; NEW Supabase Setup
              </h1>
              <span className="text-[11px] font-semibold px-2.5 py-0.5 rounded border border-blue-300 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300">
                {status.db_project_label || 'NEW Supabase Project'}
              </span>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              Connect your NEW Supabase PostgreSQL project safely without resetting your Admin account,
              RBAC roles, JWT keys, or master encryption key.
            </p>
          </div>
          <span
            className={`text-xs font-semibold px-3 py-1.5 rounded-md border ${
              status.overall_status === 'Online'
                ? 'border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40'
                : status.overall_status === 'Offline'
                  ? 'border-red-300 dark:border-red-800 text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40'
                  : 'border-amber-300 dark:border-amber-800 text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40'
            }`}
          >
            System State: {status.overall_status}
          </span>
        </div>

        {/* Preserved Application & Security Notice */}
        <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 text-xs text-slate-700 dark:text-slate-300 flex flex-wrap items-center justify-between gap-3">
          <div>
            <strong className="text-slate-900 dark:text-slate-100">
              Existing App &amp; Security Preserved:
            </strong>{' '}
            Admin account, RBAC permissions, JWT secrets (
            {status.has_jwt_secrets ? 'Preserved' : 'Not Generated Yet'}), and{' '}
            <code className="font-mono">RG_CONFIG_ENCRYPTION_KEY</code> remain intact when switching
            to a NEW Supabase project.
          </div>
          <span
            className={`text-[11px] font-semibold px-2.5 py-1 rounded border ${
              status.database_setup_complete
                ? 'border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40'
                : 'border-amber-300 dark:border-amber-800 text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40'
            }`}
          >
            Database Setup:{' '}
            {status.database_setup_complete
              ? 'Complete (20/20 Tables Verified)'
              : `Incomplete (${status.verified_tables_count}/20 Tables)`}
          </span>
        </div>

        {/* 6 Live Dashboard Status Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
          <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              Supabase (NEW Project)
            </div>
            <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
              {status.has_database_config ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <Clock className="w-4 h-4 text-amber-500 shrink-0" />
              )}
              <span>{status.has_database_config ? 'Configured' : 'Not Configured'}</span>
            </div>
            <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">
              {status.masked_db_host || 'Enter NEW Supabase host below'}
            </div>
          </div>

          <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              Database connection (Pre-Migration)
            </div>
            <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
              {status.database_status === 'Connected' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-500 shrink-0" />
              )}
              <span>
                {status.database_status === 'Connected' ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1 truncate">
              {status.database_status === 'Not Configured'
                ? 'Save NEW Supabase credentials first'
                : status.last_db_test_message || 'Pending pre-migration connection test'}
            </div>
          </div>

          <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              20-Table Schema Verification
            </div>
            <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
              {status.tables_verified ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <Clock className="w-4 h-4 text-amber-500 shrink-0" />
              )}
              <span>
                {status.tables_verified
                  ? 'All 20/20 Verified'
                  : `${status.verified_tables_count}/20 Verified`}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1 truncate">
              {status.last_table_verify_at
                ? `Checked ${new Date(status.last_table_verify_at).toLocaleTimeString()}`
                : 'SQL never run automatically'}
            </div>
          </div>

          <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              JWT security &amp; Encryption Key
            </div>
            <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
              {status.has_jwt_secrets ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <Clock className="w-4 h-4 text-amber-500 shrink-0" />
              )}
              <span>{status.has_jwt_secrets ? 'Configured & Preserved' : 'Not Configured'}</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">
              Key #{km?.active_key_fingerprint || 'pending'} · {km?.key_source || pDetails.key_source}
            </div>
          </div>

          <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">FastAPI backend</div>
            <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
              {status.fastapi_status === 'Online' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-500 shrink-0" />
              )}
              <span>{status.fastapi_status === 'Online' ? 'Online' : 'Offline'}</span>
            </div>
            <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">
              {status.fastapi_base_url || 'Not deployed yet'}
            </div>
          </div>

          <div className="p-3.5 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              Configuration persistence
            </div>
            <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
              {status.persistence_verified ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <Clock className="w-4 h-4 text-amber-500 shrink-0" />
              )}
              <span>{status.persistence_verified ? 'Verified' : 'Not Verified'}</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Saved:{' '}
              {status.last_saved_at ? new Date(status.last_saved_at).toLocaleString() : 'Not yet'}{' '}
              · Restarts: {pDetails.verified_restarts_count}
            </div>
          </div>
        </div>

        {/* Quick Dashboard Action Buttons */}
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            type="button"
            onClick={handleTestDbConnection}
            disabled={busyAction === 'test_db' || !status.has_database_config}
            className="px-3.5 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50"
          >
            {busyAction === 'test_db'
              ? 'Testing NEW Supabase Connection...'
              : 'Test Database Connection'}
          </button>
          <button
            type="button"
            onClick={handleVerifyTables}
            disabled={busyAction === 'verify_tables' || !status.has_database_config}
            className="px-3.5 py-2 text-xs font-semibold rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
          >
            {busyAction === 'verify_tables'
              ? 'Checking 20 Tables...'
              : 'Verify All 20 Required Tables'}
          </button>
          <button
            type="button"
            onClick={handleTestBackend}
            disabled={busyAction === 'test_backend' || !status.fastapi_base_url}
            className="px-3.5 py-2 text-xs font-semibold rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
          >
            {busyAction === 'test_backend' ? 'Testing Backend...' : 'Test Backend Connection'}
          </button>
          <button
            type="button"
            onClick={handleVerifyPersistence}
            disabled={busyAction === 'verify_persistence'}
            className="px-3.5 py-2 text-xs font-semibold rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
          >
            {busyAction === 'verify_persistence' ? 'Verifying...' : 'Verify Persistent Storage'}
          </button>
        </div>

        {pDetails.warning && (
          <div className="p-3 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-xs text-amber-900 dark:text-amber-200 leading-relaxed">
            <strong>Storage Durability Notice:</strong> {pDetails.warning}
          </div>
        )}
      </section>

      {error && (
        <div className="p-3.5 rounded-md border border-red-300 dark:border-red-900/70 bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-300 text-xs flex items-start gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {notice && (
        <div className="p-3.5 rounded-md border border-emerald-300 dark:border-emerald-900/70 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 text-xs">
          {notice}
        </div>
      )}

      {/* Step 0 (Before NEW Supabase): Safe RG_CONFIG_ENCRYPTION_KEY Migration Workflow */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-semibold">
                  Pre-Connection Step — Safe RG_CONFIG_ENCRYPTION_KEY Migration
                </h2>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950">
                  Active Key #{km.active_key_fingerprint}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Generates a new 256-bit key server-side, creates a recoverable encrypted backup,
                re-encrypts &amp; verifies all secrets, and keeps your old key active until you
                explicitly confirm activation. Zero keys or passwords are ever exposed.
              </p>
            </div>
          </div>
          <span
            className={`text-xs font-semibold px-2.5 py-1 rounded border ${
              km.migration_state === 'staged_verified'
                ? 'border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40'
                : km.migration_state === 'activated'
                  ? 'border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40'
                  : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'
            }`}
          >
            {km.migration_state === 'staged_verified'
              ? 'Staged & Verified (Awaiting Confirmation)'
              : km.migration_state === 'activated'
                ? 'Migrated & Verified'
                : 'Ready to Migrate'}
          </span>
        </div>

        {km.hosting_env_notice && (
          <div className="p-3 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-xs text-amber-900 dark:text-amber-200">
            <strong>Hosting Environment Sync Note:</strong> {km.hosting_env_notice}
          </div>
        )}

        {km.last_migration && km.migration_state !== 'staged_verified' && (
          <div className="p-3.5 rounded-md border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-950/20 text-xs space-y-1">
            <div className="font-semibold text-emerald-800 dark:text-emerald-300">
              Latest Key Migration Completed &amp; Post-Activation Decryption Verified
            </div>
            <div className="text-slate-700 dark:text-slate-300 font-mono text-[11px]">
              {km.last_migration.old_key_fingerprint} → {km.last_migration.new_key_fingerprint} ·
              Activated {new Date(km.last_migration.activated_at).toLocaleString()} · Migrated:{' '}
              {km.last_migration.migrated_secret_fields.join(', ') || 'config store'}
            </div>
          </div>
        )}

        {km.migration_state === 'staged_verified' && km.staged ? (
          <div className="p-4 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-950/20 space-y-4">
            <div className="space-y-1 text-xs">
              <div className="font-semibold text-amber-900 dark:text-amber-200">
                Stage 1 Complete — New Key Tested &amp; Old Key Still Active (Safe to Review)
              </div>
              <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300">
                Old Key #{km.staged.old_key_fingerprint} → Staged New 256-Bit Key #
                {km.staged.new_key_fingerprint}
              </div>
              <div className="text-slate-700 dark:text-slate-300">
                Re-encrypted &amp; decryption-verified fields:{' '}
                <code className="font-mono">
                  {km.staged.migrated_secret_fields.join(', ') || 'encrypted store initialized'}
                </code>
              </div>
              <div className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                Pre-Migration Backup SHA-256: {km.staged.pre_migration_backup_sha256.slice(0, 20)}…
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={handleDownloadPreMigrationBackup}
                disabled={busyAction === 'key_mig_backup'}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Pre-Migration Encrypted Backup (.rgcfg)</span>
              </button>
            </div>

            <form onSubmit={handleActivateKeyMigration} className="space-y-3 pt-3 border-t border-amber-200 dark:border-amber-900/60">
              <div>
                <label className="block text-xs font-medium text-slate-800 dark:text-slate-200 mb-1">
                  Stage 2 — Explicit Administrator Confirmation: type{' '}
                  <code className="font-mono font-semibold">CONFIRM KEY ROTATION</code> to activate
                  the new 256-bit encryption key
                </label>
                <input
                  type="text"
                  required
                  value={activationConfirmation}
                  onChange={(e) => setActivationConfirmation(e.target.value)}
                  placeholder="CONFIRM KEY ROTATION"
                  className="w-full max-w-sm px-3 py-2 text-xs font-mono rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="submit"
                  disabled={
                    busyAction === 'key_mig_activate' ||
                    activationConfirmation.trim() !== 'CONFIRM KEY ROTATION'
                  }
                  className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50"
                >
                  {busyAction === 'key_mig_activate'
                    ? 'Activating & Verifying...'
                    : 'Activate New 256-Bit Encryption Key'}
                </button>
                <button
                  type="button"
                  onClick={handleCancelKeyMigration}
                  disabled={busyAction === 'key_mig_cancel'}
                  className="px-4 py-2 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  Cancel (Keep Current Key)
                </button>
              </div>
            </form>
          </div>
        ) : (
          <form onSubmit={handlePrepareKeyMigration} className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Pre-Migration Encrypted Backup Passphrase (required, 12+ characters)
                </label>
                <input
                  type="password"
                  required
                  minLength={12}
                  value={migrationBackupPassphrase}
                  onChange={(e) => setMigrationBackupPassphrase(e.target.value)}
                  placeholder="Enter strong passphrase for pre-migration .rgcfg backup"
                  className="w-full px-3 py-2 text-xs rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
              <div className="flex flex-col justify-end">
                <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400 cursor-pointer pb-2">
                  <input
                    type="checkbox"
                    checked={showCustomNewKey}
                    onChange={(e) => setShowCustomNewKey(e.target.checked)}
                  />
                  <span>
                    Optional: Enter hosting-generated key instead of auto-generating on server
                  </span>
                </label>
              </div>
            </div>

            {showCustomNewKey && (
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  New Hosting RG_CONFIG_ENCRYPTION_KEY (write-only, 32+ chars / 64 hex chars)
                </label>
                <input
                  type="password"
                  minLength={32}
                  value={customNewKeyInput}
                  onChange={(e) => setCustomNewKeyInput(e.target.value)}
                  placeholder="Paste new 256-bit key from Render/Railway Secret Manager (never stored in browser)"
                  className="w-full px-3 py-2 text-xs font-mono rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
            )}

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="submit"
                disabled={busyAction === 'key_mig_prepare'}
                className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50"
              >
                {busyAction === 'key_mig_prepare'
                  ? 'Staging Backup & Re-Encrypting...'
                  : '1. Prepare 256-Bit Key Migration & Verify Backup'}
              </button>
              {km.has_pre_migration_backup && (
                <button
                  type="button"
                  onClick={handleDownloadPreMigrationBackup}
                  disabled={busyAction === 'key_mig_backup'}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Latest Pre-Migration Backup (.rgcfg)</span>
                </button>
              )}
            </div>
          </form>
        )}
      </section>

      {/* Step 1: Reset & Enter NEW Supabase Project Credentials */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            <div>
              <h2 className="text-base font-semibold">
                Step 1 — NEW Supabase Project Database Credentials
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Enter your NEW Supabase hostname, port, username, database name, and password.
                Credentials are AES-256-GCM encrypted on the server only.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleResetDatabaseTarget}
              disabled={busyAction === 'reset_db'}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 hover:bg-amber-100 dark:hover:bg-amber-950/70"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Only DB Settings for NEW Project</span>
            </button>
            {status.has_database_config && !editingDb && (
              <button
                type="button"
                onClick={() => setEditingDb(true)}
                className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                Replace Credentials
              </button>
            )}
          </div>
        </div>

        {status.has_database_config && !editingDb ? (
          <div className="p-4 rounded-md border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-950/20 text-xs space-y-1.5">
            <div className="font-semibold text-emerald-800 dark:text-emerald-300">
              NEW Supabase Project credentials saved &amp; encrypted server-side (password hidden).
            </div>
            <div className="font-mono text-slate-600 dark:text-slate-300">
              Host: {status.masked_db_host} · User: {status.supabase_user} · DB:{' '}
              {status.supabase_db_name} · SSL: {status.db_ssl_require ? 'Required' : 'Off'} · Pooler:{' '}
              {status.db_pooler_mode ? 'Supavisor (6543)' : 'Direct (5432)'}
            </div>
          </div>
        ) : (
          <form onSubmit={handleSaveDatabase} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Quick Paste: NEW Supabase Connection URI (optional — auto-fills host, user, port, password)
              </label>
              <input
                type="password"
                value={connectionUri}
                onChange={(e) => setConnectionUri(e.target.value)}
                placeholder="postgresql://postgres.<new_project_ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres"
                className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  NEW Supabase Hostname
                </label>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="aws-0-ap-southeast-1.pooler.supabase.com"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Port (6543 Pooler / 5432 Direct)
                </label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-full px-3 py-2 text-sm font-mono tabular-nums rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Database Name
                </label>
                <input
                  type="text"
                  value={dbName}
                  onChange={(e) => setDbName(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Database Username
                </label>
                <input
                  type="text"
                  value={dbUser}
                  onChange={(e) => setDbUser(e.target.value)}
                  placeholder="postgres.<new_project_ref>"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  NEW Supabase Database Password{' '}
                  {status.has_database_config ? '(leave blank only if keeping current saved password)' : ''}
                </label>
                <input
                  type="password"
                  value={dbPassword}
                  onChange={(e) => setDbPassword(e.target.value)}
                  placeholder="Enter password for your NEW Supabase project"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-6 text-xs text-slate-700 dark:text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sslRequire}
                  onChange={(e) => setSslRequire(e.target.checked)}
                />
                <span>Require TLS SSL (Supabase mandatory)</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={poolerMode}
                  onChange={(e) => setPoolerMode(e.target.checked)}
                />
                <span>Supabase Supavisor Pooler Mode (port 6543)</span>
              </label>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="submit"
                disabled={busyAction === 'save_db'}
                className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white"
              >
                {busyAction === 'save_db'
                  ? 'Encrypting & Saving...'
                  : 'Save NEW Supabase Credentials'}
              </button>
              {status.has_database_config && (
                <button
                  type="button"
                  onClick={() => setEditingDb(false)}
                  className="px-4 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700"
                >
                  Cancel
                </button>
              )}
            </div>
          </form>
        )}
      </section>

      {/* Step 2: Pre-Migration Connection Test */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <RefreshCw className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            <div>
              <h2 className="text-base font-semibold">
                Step 2 — Pre-Migration Connection Test (Before Running SQL)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Verifies hostname, port, username, password, and TLS SSL against your NEW Supabase
                project without executing any SQL or modifying tables.
              </p>
            </div>
          </div>
          <span
            className={`text-xs font-semibold px-2.5 py-1 rounded border ${
              status.last_db_test_ok
                ? 'border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40'
                : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'
            }`}
          >
            {status.last_db_test_ok ? 'Connection Verified' : 'Test Required'}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleTestDbConnection}
            disabled={busyAction === 'test_db' || !status.has_database_config}
            className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50"
          >
            {busyAction === 'test_db'
              ? 'Testing NEW Supabase Connection...'
              : 'Test NEW Supabase Connection (Pre-Migration)'}
          </button>
        </div>

        {status.last_db_test_message && (
          <div
            className={`p-3 rounded-md border text-xs ${
              status.last_db_test_ok
                ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300'
                : 'border-red-200 dark:border-red-900/60 bg-red-50/50 dark:bg-red-950/20 text-red-700 dark:text-red-300'
            }`}
          >
            {status.last_db_test_message}
          </div>
        )}
      </section>

      {/* Step 3: Manual 20-Table SQL Execution in NEW Supabase SQL Editor */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <Database className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
          <div>
            <h2 className="text-base font-semibold">
              Step 3 — Copy &amp; Run 20-Table SQL Schema in NEW Supabase SQL Editor
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              SQL is never executed automatically. After Step 2 succeeds, copy the 20-table schema
              and run it manually inside your NEW Supabase project.
            </p>
          </div>
        </div>

        {!status.last_db_test_ok && (
          <div className="p-3 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-xs text-amber-900 dark:text-amber-200">
            Recommended: Complete <strong>Step 2 (Pre-Migration Connection Test)</strong> first so
            you confirm credentials work before running the SQL schema.
          </div>
        )}

        <ol className="list-decimal list-inside space-y-1.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
          <li>
            Click <strong>Copy 20-Table Database Schema SQL</strong> below.
          </li>
          <li>
            Click <strong>Open Supabase Dashboard</strong>, select your{' '}
            <strong>NEW Supabase project</strong>, and click <strong>SQL Editor → New query</strong>.
          </li>
          <li>
            Paste the copied SQL into the query editor and click <strong>Run</strong> (wait for{' '}
            <em>Success</em>).
          </li>
          <li>
            Return here and proceed to <strong>Step 4</strong> to verify all 20 tables exist.
          </li>
        </ol>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleCopySql}
            disabled={busyAction === 'copy_sql'}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>
              {copiedSql ? 'Copied 20-Table Schema SQL' : 'Copy 20-Table Database Schema SQL'}
            </span>
          </button>
          <a
            href="https://supabase.com/dashboard"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <span>Open Supabase Dashboard</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </section>

      {/* Step 4: Verify All 20 Required Tables */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Table2 className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            <div>
              <h2 className="text-base font-semibold">
                Step 4 — Verify All 20 Required Tables ({status.verified_tables_count}/20)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Database setup is only marked Complete after all 20 required tables are verified in
                your NEW Supabase project via read-only inspection.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleVerifyTables}
            disabled={busyAction === 'verify_tables' || !status.has_database_config}
            className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50"
          >
            {busyAction === 'verify_tables'
              ? 'Verifying 20 Tables...'
              : 'Verify All 20 Required Tables'}
          </button>
        </div>

        {status.last_table_verify_message && (
          <div
            className={`p-3 rounded-md border text-xs ${
              status.tables_verified
                ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300'
                : 'border-amber-200 dark:border-amber-900/60 bg-amber-50/50 dark:bg-amber-950/20 text-amber-800 dark:text-amber-300'
            }`}
          >
            {status.last_table_verify_message}
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
          {requiredTables.map((tableName) => {
            const exists = verifiedSet.has(tableName);
            return (
              <div
                key={tableName}
                className={`px-2.5 py-1.5 rounded border text-[11px] font-mono flex items-center justify-between gap-1.5 ${
                  exists
                    ? 'border-emerald-200 dark:border-emerald-900/70 bg-emerald-50/40 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300'
                    : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 text-slate-600 dark:text-slate-400'
                }`}
              >
                <span className="truncate">{tableName}</span>
                {exists ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                ) : (
                  <Clock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Step 5: Preserved JWT Security & Hosting Env Export */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <KeyRound className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
          <h2 className="text-base font-semibold">
            Step 5 — Preserved JWT Security &amp; Hosting Secrets
          </h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          Your current JWT keys and <code className="font-mono">RG_CONFIG_ENCRYPTION_KEY</code>{' '}
          are preserved automatically across database resets. Download{' '}
          <code className="font-mono">rgstudio-backend-template.env</code> (with secrets safely
          redacted) for setting up your hosting environment variables.
        </p>

        <div className="flex flex-wrap items-center gap-3">
          {!status.has_jwt_secrets ? (
            <button
              type="button"
              onClick={() => handleGenerateSecrets(false)}
              disabled={busyAction === 'gen_secrets'}
              className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white"
            >
              Generate Server Security Secrets
            </button>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Current JWT Secrets &amp; Master Encryption Key Preserved</span>
            </span>
          )}

          <button
            type="button"
            onClick={handleDownloadEnv}
            disabled={busyAction === 'download_env' || !status.has_database_config || !status.has_jwt_secrets}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Hosting .env Template (Redacted)</span>
          </button>
        </div>

        {status.has_jwt_secrets && (
          <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400 cursor-pointer">
              <input
                type="checkbox"
                checked={confirmRotateKeys}
                onChange={(e) => setConfirmRotateKeys(e.target.checked)}
              />
              <span>
                Advanced: Explicitly rotate JWT keys (leave unchecked to preserve existing sessions
                and keys)
              </span>
            </label>
            {confirmRotateKeys && (
              <button
                type="button"
                onClick={() => handleGenerateSecrets(true)}
                disabled={busyAction === 'gen_secrets'}
                className="px-3.5 py-1.5 text-xs font-semibold rounded-md border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/40"
              >
                Confirm Rotate JWT Keys
              </button>
            )}
          </div>
        )}
      </section>

      {/* Step 6: Permanent FastAPI Backend URL */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <Server className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
          <h2 className="text-base font-semibold">Step 6 — Permanent FastAPI Backend URL</h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          Save your deployed FastAPI HTTPS URL here. Remember to update{' '}
          <code className="font-mono">RG_DATABASE_URL</code> and{' '}
          <code className="font-mono">RG_DATABASE_SYNC_URL</code> in Render / Railway when switching
          to your NEW Supabase project.
        </p>

        <form onSubmit={handleSaveDeployment} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
              Deployed FastAPI Backend HTTPS URL
            </label>
            <input
              type="url"
              value={fastapiUrl}
              onChange={(e) => setFastapiUrl(e.target.value)}
              placeholder="https://rg-studio-management-api.onrender.com"
              className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={busyAction === 'save_deploy'}
              className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white"
            >
              Save Backend URL Permanently
            </button>
            <button
              type="button"
              onClick={handleTestBackend}
              disabled={busyAction === 'test_backend' || !status.fastapi_base_url}
              className="px-4 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
            >
              Test Backend Connection
            </button>
          </div>
        </form>
      </section>

      {/* Encrypted Configuration Backup & Restore */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-5">
        <div className="flex items-center gap-2.5">
          <HardDrive className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
          <h2 className="text-base font-semibold">Encrypted Configuration Backup &amp; Restore</h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          Export a password-protected AES-256-GCM <code className="font-mono">.rgcfg</code> snapshot
          after connecting and verifying your NEW Supabase project.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2 border-t border-slate-200 dark:border-slate-800">
          <form onSubmit={handleExportBackup} className="space-y-3">
            <div className="text-xs font-semibold flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              <span>Export Encrypted Configuration Backup</span>
            </div>
            <input
              type="password"
              required
              minLength={12}
              value={exportPassphrase}
              onChange={(e) => setExportPassphrase(e.target.value)}
              placeholder="Backup passphrase (12+ characters)"
              className="w-full px-3 py-2 text-xs rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
            <button
              type="submit"
              disabled={busyAction === 'export_backup'}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Encrypted Configuration Backup</span>
            </button>
          </form>

          <form onSubmit={handleRestoreBackup} className="space-y-3">
            <div className="text-xs font-semibold flex items-center gap-1.5">
              <Upload className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              <span>Restore Configuration Backup</span>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".rgcfg,.json"
              onChange={handleBackupFileSelected}
              className="block w-full text-xs text-slate-600 dark:text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-300 dark:file:border-slate-700 file:text-xs file:font-medium file:bg-slate-100 dark:file:bg-slate-800"
            />
            {restoreFileName && (
              <div className="text-[11px] font-mono text-slate-500">Loaded: {restoreFileName}</div>
            )}
            <input
              type="password"
              required
              value={restorePassphrase}
              onChange={(e) => setRestorePassphrase(e.target.value)}
              placeholder="Enter backup decryption passphrase"
              className="w-full px-3 py-2 text-xs rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
            <button
              type="submit"
              disabled={busyAction === 'restore_backup' || !restoreBackupJson}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Restore Configuration Backup</span>
            </button>
          </form>
        </div>
      </section>
    </div>
  );
};
