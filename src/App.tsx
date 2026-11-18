import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  FolderGit2,
  LayoutDashboard,
  LogOut,
  Moon,
  RefreshCw,
  Settings,
  Shield,
  Smartphone,
  Sun,
  Users,
  Wifi,
  WifiOff,
  Youtube,
  Mail,
  CreditCard,
  FileBarChart2,
  ArrowLeftRight,
  Tv,
} from 'lucide-react';
import { AuthGate } from './components/AuthGate';
import { ArchitectureBlueprintView } from './components/ArchitectureBlueprintView';
import { AdminInfraSetupView } from './components/AdminInfraSetupView';
import { UserManagementView } from './components/UserManagementView';
import { AuditLogEntry, ConnectionState, RoleCode, UserSummary } from './types/auth';
import {
  ApiDiagnostic,
  apiRequest,
  fetchSandboxHealth,
  fetchSetupStatus,
} from './lib/apiClient';

type NavItem = {
  id: string;
  label: string;
  phase: string;
  icon: typeof LayoutDashboard;
  roles: RoleCode[];
};

const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    phase: 'Phase 1',
    icon: LayoutDashboard,
    roles: ['admin', 'manager', 'employee'],
  },
  {
    id: 'infra',
    label: 'Infrastructure Settings',
    phase: 'Phase 1',
    icon: Shield,
    roles: ['admin'],
  },
  {
    id: 'blueprint',
    label: 'Phase 1 Architecture',
    phase: 'Phase 1',
    icon: FolderGit2,
    roles: ['admin', 'manager', 'employee'],
  },
  {
    id: 'users',
    label: 'User Management',
    phase: 'Phase 1',
    icon: Users,
    roles: ['admin'],
  },
  {
    id: 'audit',
    label: 'Activity Logs',
    phase: 'Phase 1 Auth / Phase 5 Full',
    icon: Activity,
    roles: ['admin'],
  },
  {
    id: 'employees',
    label: 'Employees',
    phase: 'Phase 2',
    icon: Users,
    roles: ['admin', 'manager'],
  },
  {
    id: 'mobiles',
    label: 'Mobile Inventory',
    phase: 'Phase 2',
    icon: Smartphone,
    roles: ['admin', 'manager', 'employee'],
  },
  {
    id: 'sims',
    label: 'SIM Management',
    phase: 'Phase 2',
    icon: CreditCard,
    roles: ['admin', 'manager', 'employee'],
  },
  {
    id: 'gmail',
    label: 'Gmail Accounts',
    phase: 'Phase 3',
    icon: Mail,
    roles: ['admin', 'manager', 'employee'],
  },
  {
    id: 'youtube',
    label: 'YouTube Accounts',
    phase: 'Phase 3',
    icon: Youtube,
    roles: ['admin', 'manager', 'employee'],
  },
  {
    id: 'company_channels',
    label: 'My Running Channels',
    phase: 'Phase 3',
    icon: Tv,
    roles: ['admin', 'manager'],
  },
  {
    id: 'assignments',
    label: 'Assignments',
    phase: 'Phase 4',
    icon: ArrowLeftRight,
    roles: ['admin', 'manager'],
  },
  {
    id: 'reports',
    label: 'Reports',
    phase: 'Phase 4',
    icon: FileBarChart2,
    roles: ['admin', 'manager'],
  },
  {
    id: 'settings',
    label: 'Settings & Theme',
    phase: 'Phase 1 / Phase 5',
    icon: Settings,
    roles: ['admin', 'manager', 'employee'],
  },
];

const SESSION_STORAGE_KEY = 'rgstudio_auth_session';

interface SavedSession {
  token: string;
  user: UserSummary;
}

function readSavedSession(): SavedSession | null {
  try {
    const raw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as SavedSession;
    if (parsed && typeof parsed.token === 'string' && parsed.user?.id) {
      return parsed;
    }
  } catch {
    // Ignore corrupted storage
  }
  return null;
}

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('rgstudio_theme');
    return saved === 'light' ? 'light' : 'dark';
  });
  const initialSession = useMemo(() => readSavedSession(), []);
  const [setupChecked, setSetupChecked] = useState(false);
  const [requiresAdminSetup, setRequiresAdminSetup] = useState(false);
  const [fastapiConfigured, setFastapiConfigured] = useState(false);
  const [savedFastapiUrl, setSavedFastapiUrl] = useState('');
  const [overallInfraStatus, setOverallInfraStatus] = useState<
    'Online' | 'Offline' | 'Configuration Required'
  >('Configuration Required');
  const [initialDiagnostic, setInitialDiagnostic] = useState<ApiDiagnostic | null>(null);
  const setupNeedsRefreshRef = useRef(false);
  const [token, setToken] = useState<string | null>(() => initialSession?.token ?? null);
  const [user, setUser] = useState<UserSummary | null>(() => initialSession?.user ?? null);
  const [activeView, setActiveView] = useState<string>('dashboard');
  const [connectionState, setConnectionState] = useState<ConnectionState>('Online');
  const [offlineSimulated, setOfflineSimulated] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [rbacProbeResult, setRbacProbeResult] = useState<string | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('rgstudio_theme', theme);
  }, [theme]);

  const checkSetupAndSession = useCallback(async (): Promise<ApiDiagnostic> => {
    const setupResult = await fetchSetupStatus();
    setInitialDiagnostic(setupResult.diagnostic);

    if (setupResult.ok && setupResult.data) {
      setupNeedsRefreshRef.current = false;
      setRequiresAdminSetup(Boolean(setupResult.data.requires_admin_setup));
      setFastapiConfigured(Boolean(setupResult.data.fastapi_configured));
      setSavedFastapiUrl(setupResult.data.fastapi_base_url || '');
      if (setupResult.data.overall_infra_status) {
        setOverallInfraStatus(setupResult.data.overall_infra_status);
      }
      if (!offlineSimulated) {
        setConnectionState('Online');
      }

      const saved = readSavedSession();
      if (saved) {
        const meResult = await apiRequest<UserSummary>('/auth/me', {
          headers: { Authorization: `Bearer ${saved.token}` },
        });
        if (meResult.ok && meResult.data) {
          setToken(saved.token);
          setUser(meResult.data);
          localStorage.setItem(
            SESSION_STORAGE_KEY,
            JSON.stringify({ token: saved.token, user: meResult.data })
          );
        } else if (meResult.diagnostic.httpStatus === 401 || meResult.diagnostic.httpStatus === 403) {
          localStorage.removeItem(SESSION_STORAGE_KEY);
          setToken(null);
          setUser(null);
        }
      }
    } else {
      setupNeedsRefreshRef.current = true;
      setConnectionState('Offline');
    }

    setSetupChecked(true);
    return setupResult.diagnostic;
  }, [offlineSimulated]);

  useEffect(() => {
    checkSetupAndSession();
  }, [checkSetupAndSession]);

  useEffect(() => {
    if (offlineSimulated) {
      setConnectionState('Offline');
      return;
    }
    let cancelled = false;
    const probe = async () => {
      const health = await fetchSandboxHealth();
      if (cancelled) return;
      if (health.ok && health.data?.status === 'online') {
        setConnectionState('Online');
        setFastapiConfigured(Boolean(health.data.fastapi_configured));
        setSavedFastapiUrl(health.data.fastapi_base_url || '');
        if (health.data.overall_infra_status) {
          setOverallInfraStatus(health.data.overall_infra_status);
        }
        if (setupNeedsRefreshRef.current) {
          const refreshed = await fetchSetupStatus();
          if (!cancelled && refreshed.ok && refreshed.data) {
            setupNeedsRefreshRef.current = false;
            setRequiresAdminSetup(Boolean(refreshed.data.requires_admin_setup));
            setInitialDiagnostic(refreshed.diagnostic);
          }
        }
      } else {
        setupNeedsRefreshRef.current = true;
        setConnectionState('Offline');
        setInitialDiagnostic(health.diagnostic);
      }
    };
    probe();
    const id = window.setInterval(probe, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [offlineSimulated]);

  const loadAuditLogs = useCallback(async () => {
    if (!token || user?.role_code !== 'admin') return;
    try {
      const res = await fetch('/api/v1/audit-logs', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        setAuditLogs(await res.json());
      }
    } catch {
      // Keep existing cached logs if offline
    }
  }, [token, user]);

  useEffect(() => {
    if (activeView === 'audit' && user?.role_code === 'admin') {
      loadAuditLogs();
    }
  }, [activeView, user, loadAuditLogs]);

  const handleToggleTheme = async () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    if (token && connectionState !== 'Offline') {
      try {
        await fetch('/api/v1/auth/me/theme', {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ theme_preference: next }),
        });
      } catch {
        // Local persistence still applies
      }
    }
  };

  const handleLogout = async () => {
    if (token) {
      try {
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Ignore network errors on logout
      }
    }
    localStorage.removeItem(SESSION_STORAGE_KEY);
    setToken(null);
    setUser(null);
    setAuditLogs([]);
    setRbacProbeResult(null);
    setActiveView('dashboard');
  };

  const handleVerifyAdminGuard = async () => {
    if (!token) return;
    setConnectionState('Synchronizing');
    try {
      const res = await fetch('/api/v1/users', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      setRbacProbeResult(
        `GET /api/v1/users -> HTTP ${res.status} (${
          res.ok ? `${data.length} records returned` : data.detail
        })`
      );
    } catch {
      setRbacProbeResult('Request failed while offline.');
    } finally {
      setConnectionState(offlineSimulated ? 'Offline' : 'Online');
    }
  };

  const visibleNav = useMemo(() => {
    if (!user) return [];
    return NAV_ITEMS.filter((item) => item.roles.includes(user.role_code));
  }, [user]);

  if (!setupChecked) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 text-sm">
        Checking RG Studio Management System status...
      </div>
    );
  }

  if (!token || !user) {
    return (
      <AuthGate
        requiresAdminSetup={requiresAdminSetup}
        fastapiConfigured={fastapiConfigured}
        connectionState={connectionState}
        initialDiagnostic={initialDiagnostic}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        onRetryConnection={checkSetupAndSession}
        onAdminCreated={() => setRequiresAdminSetup(false)}
        onAuthenticated={(accessToken, authedUser, rememberMe) => {
          setToken(accessToken);
          setUser(authedUser);
          setActiveView('dashboard');
          if (rememberMe) {
            localStorage.setItem(
              SESSION_STORAGE_KEY,
              JSON.stringify({ token: accessToken, user: authedUser })
            );
          } else {
            localStorage.removeItem(SESSION_STORAGE_KEY);
          }
        }}
      />
    );
  }

  const activeNavItem = NAV_ITEMS.find((n) => n.id === activeView) || NAV_ITEMS[0];

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col">
        <div className="px-5 py-5 border-b border-slate-200 dark:border-slate-800">
          <div className="text-sm font-bold tracking-tight text-slate-900 dark:text-slate-100">
            RG STUDIO
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Management System · Phase 1
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {visibleNav.map((item) => {
            const Icon = item.icon;
            const active = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveView(item.id)}
                className={`w-full flex items-center justify-between gap-2 px-3 py-2 rounded-md text-xs font-medium transition-colors text-left ${
                  active
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <span className="flex items-center gap-2.5 truncate">
                  <Icon className="w-4 h-4 shrink-0" />
                  <span className="truncate">{item.label}</span>
                </span>
                {item.phase !== 'Phase 1' && (
                  <span
                    className={`text-[10px] font-mono shrink-0 ${
                      active ? 'text-blue-100' : 'text-slate-400 dark:text-slate-500'
                    }`}
                  >
                    {item.phase.replace('Phase ', 'P')}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
          <div className="text-xs">
            <div className="font-semibold text-slate-900 dark:text-slate-100 truncate">
              {user.full_name}
            </div>
            <div className="text-slate-500 dark:text-slate-400 font-mono">
              @{user.username} · {user.role_name}
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Column */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 px-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between gap-6">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-500 dark:text-slate-400">RG Studio</span>
            <span className="text-slate-400">/</span>
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {activeNavItem.label}
            </span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setOfflineSimulated((v) => !v)}
              title="Toggle simulated Offline read-only mode"
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                connectionState === 'Online'
                  ? 'border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40'
                  : connectionState === 'Synchronizing'
                    ? 'border-amber-300 dark:border-amber-800 text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40'
                    : 'border-red-300 dark:border-red-800 text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40'
              }`}
            >
              {connectionState === 'Offline' ? (
                <WifiOff className="w-3.5 h-3.5" />
              ) : (
                <Wifi className="w-3.5 h-3.5" />
              )}
              <span>{connectionState}</span>
            </button>

            <button
              type="button"
              onClick={handleToggleTheme}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              {theme === 'dark' ? (
                <Sun className="w-3.5 h-3.5" />
              ) : (
                <Moon className="w-3.5 h-3.5" />
              )}
              <span>{theme === 'dark' ? 'Light' : 'Dark'}</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-6 overflow-y-auto">
          {connectionState === 'Offline' && (
            <div className="mb-6 p-3.5 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-xs text-amber-900 dark:text-amber-200">
              Client is in Offline mode. Only safely cached authorized records are viewable;
              account creation and operational mutations are disabled until Online.
            </div>
          )}

          {activeView === 'dashboard' && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6">
                <h1 className="text-xl font-semibold tracking-tight">
                  Phase 1 Foundation Active — {user.role_name} Workspace
                </h1>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-1.5 max-w-3xl">
                  This web workbench mirrors the PySide6 desktop shell and exercises real Phase 1
                  backend authentication, role-based access control, and audit logging. Production
                  Python FastAPI, Alembic migrations, and PySide6 desktop source files reside in{' '}
                  <code className="font-mono text-xs">backend/</code>,{' '}
                  <code className="font-mono text-xs">migrations/</code>, and{' '}
                  <code className="font-mono text-xs">desktop/</code>.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6 pt-6 border-t border-slate-200 dark:border-slate-800">
                  <div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Authenticated Account
                    </div>
                    <div className="text-sm font-semibold mt-1">{user.full_name}</div>
                    <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                      {user.email}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Assigned Role & Permissions
                    </div>
                    <div className="text-sm font-semibold mt-1">{user.role_name}</div>
                    <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 mt-0.5">
                      {user.permissions.length} granted capabilities
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Synchronization &amp; Infrastructure
                    </div>
                    <div className="text-sm font-semibold mt-1">
                      {connectionState} · Infra: {overallInfraStatus}
                    </div>
                    <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                      {savedFastapiUrl || 'FastAPI URL not deployed yet'}
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-3">
                  <h2 className="text-sm font-semibold">Granted Permissions ({user.role_code})</h2>
                  <div className="flex flex-wrap gap-x-3 gap-y-1.5 text-xs font-mono text-slate-600 dark:text-slate-300">
                    {user.permissions.map((perm) => (
                      <span key={perm}>{perm}</span>
                    ))}
                  </div>
                </div>

                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-3">
                  <h2 className="text-sm font-semibold">Live Backend RBAC Probe</h2>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    Test server-side enforcement on Admin endpoint{' '}
                    <code className="font-mono">GET /api/v1/users</code> using your current JWT.
                  </p>
                  <button
                    type="button"
                    onClick={handleVerifyAdminGuard}
                    className="px-3.5 py-2 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors"
                  >
                    Run RBAC Check
                  </button>
                  {rbacProbeResult && (
                    <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-950 font-mono text-xs border border-slate-200 dark:border-slate-800">
                      {rbacProbeResult}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeView === 'infra' && (
            <AdminInfraSetupView
              token={token}
              currentUser={user}
              connectionState={connectionState}
            />
          )}

          {activeView === 'blueprint' && <ArchitectureBlueprintView />}

          {activeView === 'users' && (
            <UserManagementView
              token={token}
              currentUser={user}
              connectionState={connectionState}
            />
          )}

          {activeView === 'audit' && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Phase 1 Authentication & User Audit Trail</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Real server-recorded setup, login, failed login, logout, and user management events.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={loadAuditLogs}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Refresh</span>
                </button>
              </div>
              {auditLogs.length === 0 ? (
                <div className="p-6 text-xs text-slate-500">No audit events recorded yet.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-sm">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs text-slate-600 dark:text-slate-400">
                        <th className="py-2.5 px-4 font-semibold">Timestamp</th>
                        <th className="py-2.5 px-4 font-semibold">Actor</th>
                        <th className="py-2.5 px-4 font-semibold">Action</th>
                        <th className="py-2.5 px-4 font-semibold">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                      {auditLogs.map((entry) => (
                        <tr key={entry.id}>
                          <td className="py-2.5 px-4 font-mono tabular-nums text-xs text-slate-500 dark:text-slate-400">
                            {new Date(entry.created_at).toLocaleString()}
                          </td>
                          <td className="py-2.5 px-4 font-mono text-xs">
                            {entry.actor_username || 'system'}
                          </td>
                          <td className="py-2.5 px-4 font-mono text-xs font-semibold text-blue-700 dark:text-blue-400">
                            {entry.action}
                          </td>
                          <td className="py-2.5 px-4 text-xs text-slate-700 dark:text-slate-300">
                            {entry.details}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeView === 'settings' && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 max-w-2xl space-y-5">
              <div>
                <h2 className="text-base font-semibold">Workspace Appearance & Session</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  Theme preferences persist locally and synchronize with your user profile when Online.
                </p>
              </div>
              <div className="flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-800">
                <div>
                  <div className="text-sm font-medium">Interface Theme</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Active theme: {theme === 'dark' ? 'Dark Charcoal' : 'Light Surface'}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleToggleTheme}
                  className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors"
                >
                  Switch to {theme === 'dark' ? 'Light' : 'Dark'} Theme
                </button>
              </div>
              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                Database backup configuration, SHA-256 verification, and restore workflows are
                scheduled for Phase 5.
              </div>
            </div>
          )}

          {!['dashboard', 'infra', 'blueprint', 'users', 'audit', 'settings'].includes(activeView) && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 max-w-2xl">
              <div className="text-xs font-mono text-blue-600 dark:text-blue-400 mb-1">
                {activeNavItem.phase} Module
              </div>
              <h2 className="text-lg font-semibold">{activeNavItem.label}</h2>
              <p className="text-sm text-slate-600 dark:text-slate-400 mt-2 leading-relaxed">
                This navigation entry is active in the Phase 1 role-filtered shell. Per the staged
                development workflow, database tables are already provisioned in{' '}
                <code className="font-mono text-xs">migrations/001_initial_schema.sql</code> and
                functional CRUD workflows will be implemented in {activeNavItem.phase} after Phase 1
                approval.
              </p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
