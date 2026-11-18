import React, { useState } from 'react';
import {
  Lock,
  UserPlus,
  Sun,
  Moon,
  AlertCircle,
  Wifi,
  WifiOff,
  RefreshCw,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { ConnectionState, UserSummary } from '../types/auth';
import {
  ApiDiagnostic,
  createFirstRunAdmin,
  loginSandboxAccount,
  registerSandboxEmployee,
} from '../lib/apiClient';

interface AuthGateProps {
  requiresAdminSetup: boolean;
  fastapiConfigured: boolean;
  connectionState: ConnectionState;
  initialDiagnostic: ApiDiagnostic | null;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onRetryConnection: () => Promise<ApiDiagnostic>;
  onAdminCreated: () => void;
  onAuthenticated: (token: string, user: UserSummary, rememberMe: boolean) => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({
  requiresAdminSetup,
  fastapiConfigured,
  connectionState,
  initialDiagnostic,
  theme,
  onToggleTheme,
  onRetryConnection,
  onAdminCreated,
  onAuthenticated,
}) => {
  // Always default to the Login page on launch; users without an account switch to Sign Up
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [rememberMe, setRememberMe] = useState(true);

  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const [identifier, setIdentifier] = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [lastDiagnostic, setLastDiagnostic] = useState<ApiDiagnostic | null>(initialDiagnostic);
  const [showDiagnostic, setShowDiagnostic] = useState<boolean>(
    Boolean(initialDiagnostic && !initialDiagnostic.ok)
  );

  const activeDiagnostic = lastDiagnostic || initialDiagnostic;

  const switchMode = (nextMode: 'login' | 'signup') => {
    setMode(nextMode);
    setError(null);
    setNotice(null);
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setError(null);
    const diag = await onRetryConnection();
    setLastDiagnostic(diag);
    setShowDiagnostic(true);
    if (diag.ok) {
      setNotice('Phase 1 Sandbox API is Online and ready.');
    } else {
      setError(diag.reason);
    }
    setTestingConnection(false);
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      if (requiresAdminSetup) {
        const createResult = await createFirstRunAdmin({
          full_name: fullName,
          username,
          email,
          password,
        });
        setLastDiagnostic(createResult.diagnostic);

        if (!createResult.ok || !createResult.data) {
          setError(createResult.errorMessage || 'Unable to create initial Administrator.');
          setShowDiagnostic(true);
          return;
        }

        const createdAdmin = createResult.data;
        onAdminCreated();

        // Step 2: Sign in automatically so the Administrator enters the Dashboard immediately
        const loginResult = await loginSandboxAccount({
          identifier: createdAdmin.username,
          password,
          remember_me: rememberMe,
        });
        setLastDiagnostic(loginResult.diagnostic);

        if (loginResult.ok && loginResult.data) {
          onAuthenticated(loginResult.data.access_token, loginResult.data.user, rememberMe);
          return;
        }

        // Admin was created, but auto-login did not complete — switch cleanly to Sign In
        setIdentifier(createdAdmin.username);
        setNotice(
          `Administrator '@${createdAdmin.username}' was created in the Phase 1 Sandbox. Please sign in below.`
        );
        if (!loginResult.ok) {
          setShowDiagnostic(true);
        }
        setMode('login');
        return;
      }

      const regResult = await registerSandboxEmployee({
        full_name: fullName,
        username,
        email,
        password,
        remember_me: rememberMe,
      });
      setLastDiagnostic(regResult.diagnostic);

      if (!regResult.ok || !regResult.data) {
        setError(regResult.errorMessage || 'Unable to create account.');
        if (regResult.diagnostic.httpStatus === null || regResult.diagnostic.httpStatus >= 500) {
          setShowDiagnostic(true);
        }
        return;
      }
      onAuthenticated(regResult.data.access_token, regResult.data.user, rememberMe);
    } finally {
      setSubmitting(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      const loginResult = await loginSandboxAccount({
        identifier,
        password: loginPassword,
        remember_me: rememberMe,
      });
      setLastDiagnostic(loginResult.diagnostic);

      if (!loginResult.ok || !loginResult.data) {
        setError(loginResult.errorMessage || 'Authentication failed.');
        if (loginResult.diagnostic.httpStatus === null || loginResult.diagnostic.httpStatus >= 500) {
          setShowDiagnostic(true);
        }
        return;
      }
      onAuthenticated(loginResult.data.access_token, loginResult.data.user, rememberMe);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        <span className="text-base font-bold tracking-tight whitespace-nowrap shrink-0">
          RG Studio Management System
        </span>
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleTestConnection}
            disabled={testingConnection}
            className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
              connectionState === 'Online'
                ? 'border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40'
                : 'border-red-300 dark:border-red-800 text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40'
            }`}
          >
            {connectionState === 'Offline' ? (
              <WifiOff className="w-3.5 h-3.5" />
            ) : (
              <Wifi className="w-3.5 h-3.5" />
            )}
            <span>
              {testingConnection
                ? 'Checking...'
                : `Sandbox API: ${connectionState}`}
            </span>
          </button>

          <button
            type="button"
            onClick={onToggleTheme}
            className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            <span>{theme === 'dark' ? 'Light Theme' : 'Dark Theme'}</span>
          </button>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-7">
          <div className="flex items-center gap-2.5 mb-2">
            {mode === 'signup' ? (
              <UserPlus className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            ) : (
              <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            )}
            <h1 className="text-xl font-semibold tracking-tight">
              {mode === 'login'
                ? 'Sign In to RG Studio'
                : requiresAdminSetup
                  ? 'Create Administrator Account'
                  : 'Create New Account'}
            </h1>
          </div>

          <p className="text-sm text-slate-600 dark:text-slate-400 mb-4 leading-relaxed">
            {mode === 'login'
              ? 'Sign in with your username or email. Your session will stay saved so the dashboard opens automatically next time.'
              : requiresAdminSetup
                ? 'First-time setup: this account will be created as the primary system Administrator.'
                : 'Register a new Employee workspace account. Admin and Manager roles are assigned by an Administrator.'}
          </p>

          {/* Clear distinction: Phase 1 Preview Sandbox vs Production FastAPI + Supabase */}
          <div className="mb-5 p-3 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/70 text-xs space-y-1">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-slate-800 dark:text-slate-200">
                Phase 1 Sandbox Mode
              </span>
              <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                /api/v1 (Preview Server)
              </span>
            </div>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              {fastapiConfigured
                ? 'This preview uses the built-in Phase 1 Sandbox store. Your hosted FastAPI + Supabase server is configured in Admin Infrastructure Setup.'
                : 'Accounts created here use the built-in Phase 1 Sandbox API on this preview server. Production FastAPI + Supabase is not deployed yet (RG_API_BASE_URL intentionally blank).'}
            </p>
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-md border border-red-300 dark:border-red-900/70 bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-300 text-xs flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {notice && (
            <div className="mb-4 p-3 rounded-md border border-emerald-300 dark:border-emerald-900/70 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 text-xs">
              {notice}
            </div>
          )}

          {mode === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Email or Username
                </label>
                <input
                  type="text"
                  required
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="username or name@rgstudio.com"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Password
                </label>
                <input
                  type="password"
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Enter password"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-700 text-blue-600 focus:ring-blue-600"
                />
                <span>Keep me signed in (open dashboard automatically)</span>
              </label>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 px-4 text-sm font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50 whitespace-nowrap"
              >
                {submitting ? 'Signing In...' : 'Sign In'}
              </button>

              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
                <span className="text-slate-600 dark:text-slate-400">
                  Don&apos;t have an account?
                </span>
                <button
                  type="button"
                  onClick={() => switchMode('signup')}
                  className="font-semibold text-blue-600 dark:text-blue-400 hover:underline whitespace-nowrap"
                >
                  {requiresAdminSetup ? 'Sign Up (Admin Setup)' : 'Create Account (Sign Up)'}
                </button>
              </div>
            </form>
          ) : (
            <form onSubmit={handleSignUp} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g., Tariq Mahmood"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Username
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g., tariq.rg"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@rgstudio.com"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Password
                </label>
                <input
                  type="password"
                  required
                  minLength={12}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="12+ chars, upper, lower, number"
                  className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-700 text-blue-600 focus:ring-blue-600"
                />
                <span>Keep me signed in after registration</span>
              </label>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 px-4 text-sm font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50 whitespace-nowrap"
              >
                {submitting
                  ? 'Creating Account...'
                  : requiresAdminSetup
                    ? 'Create Administrator & Continue'
                    : 'Sign Up & Open Dashboard'}
              </button>

              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
                <span className="text-slate-600 dark:text-slate-400">
                  Already have an account?
                </span>
                <button
                  type="button"
                  onClick={() => switchMode('login')}
                  className="font-semibold text-blue-600 dark:text-blue-400 hover:underline whitespace-nowrap"
                >
                  Back to Sign In
                </button>
              </div>
            </form>
          )}

          {/* Visible Connection Diagnostic (never exposes passwords or secrets) */}
          <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => setShowDiagnostic((v) => !v)}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
              >
                <span>Connection Diagnostic</span>
                {showDiagnostic ? (
                  <ChevronUp className="w-3.5 h-3.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5" />
                )}
              </button>
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={testingConnection}
                className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${testingConnection ? 'animate-spin' : ''}`} />
                <span>Test Connection</span>
              </button>
            </div>

            {showDiagnostic && (
              <div className="mt-3 p-3 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-[11px] font-mono space-y-1 text-slate-700 dark:text-slate-300">
                <div>
                  <span className="text-slate-500">Target:</span>{' '}
                  {activeDiagnostic?.targetService || 'Phase 1 Sandbox API (Preview Express Server)'}
                </div>
                <div>
                  <span className="text-slate-500">Production FastAPI:</span>{' '}
                  {fastapiConfigured ? 'Configured in Admin Infra Setup' : 'Not Deployed (RG_API_BASE_URL blank)'}
                </div>
                {activeDiagnostic && (
                  <>
                    <div className="break-all">
                      <span className="text-slate-500">Request:</span> {activeDiagnostic.endpoint}
                    </div>
                    <div className="break-all">
                      <span className="text-slate-500">URL:</span> {activeDiagnostic.resolvedUrl}
                    </div>
                    <div>
                      <span className="text-slate-500">HTTP Status:</span>{' '}
                      {activeDiagnostic.httpStatus !== null
                        ? activeDiagnostic.httpStatus
                        : 'No HTTP response (network/transport)'}
                      {activeDiagnostic.contentType ? ` (${activeDiagnostic.contentType})` : ''}
                    </div>
                    <div className={activeDiagnostic.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}>
                      <span className="text-slate-500">Detail:</span> {activeDiagnostic.reason}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};
