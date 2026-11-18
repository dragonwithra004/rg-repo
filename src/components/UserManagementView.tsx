import React, { useCallback, useEffect, useState } from 'react';
import { UserPlus, RefreshCw, ShieldAlert } from 'lucide-react';
import { ConnectionState, UserSummary } from '../types/auth';

interface UserManagementViewProps {
  token: string;
  currentUser: UserSummary;
  connectionState: ConnectionState;
}

export const UserManagementView: React.FC<UserManagementViewProps> = ({
  token,
  currentUser,
  connectionState,
}) => {
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [roleCode, setRoleCode] = useState<'manager' | 'employee'>('manager');
  const [submitting, setSubmitting] = useState(false);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/users', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(`HTTP ${res.status}: ${data.detail || 'Access denied'}`);
        setUsers([]);
        return;
      }
      setUsers(data);
    } catch {
      setError('Unable to fetch user directory.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    if (connectionState === 'Offline') {
      setFormError('Offline mode is read-only. Reconnect to Online state to create users.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/v1/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          full_name: fullName,
          username,
          email,
          password,
          role_code: roleCode,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFormError(`HTTP ${res.status}: ${data.detail || 'Unable to create user'}`);
        return;
      }
      setFormSuccess(`Created ${data.role_name} account '@${data.username}'.`);
      setFullName('');
      setUsername('');
      setEmail('');
      setPassword('');
      await loadUsers();
    } catch {
      setFormError('Network error while creating user.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleStatus = async (target: UserSummary) => {
    setFormError(null);
    setFormSuccess(null);
    if (connectionState === 'Offline') {
      setFormError('Offline mode is read-only. Reconnect to modify user status.');
      return;
    }
    try {
      const res = await fetch(`/api/v1/users/${target.id}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: !target.is_active }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFormError(`HTTP ${res.status}: ${data.detail || 'Status update failed'}`);
        return;
      }
      await loadUsers();
    } catch {
      setFormError('Network error while updating account status.');
    }
  };

  if (currentUser.role_code !== 'admin' && error) {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6">
        <div className="flex items-start gap-3 text-red-700 dark:text-red-400">
          <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold">Backend RBAC Enforcement Verified</h3>
            <p className="text-xs mt-1 text-slate-600 dark:text-slate-400">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <UserPlus className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <h2 className="text-base font-semibold">Create Manager or Employee Account</h2>
          </div>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            Admin-only · Argon2id / Scrypt hashed
          </span>
        </div>

        {formError && (
          <div className="mb-4 p-3 rounded-md border border-red-300 dark:border-red-900/70 bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-300 text-xs">
            {formError}
          </div>
        )}
        {formSuccess && (
          <div className="mb-4 p-3 rounded-md border border-emerald-300 dark:border-emerald-900/70 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 text-xs">
            {formSuccess}
          </div>
        )}

        <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
              Full Name
            </label>
            <input
              type="text"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Ayesha Khan"
              className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
              Username
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="ayesha.mgr"
              className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
              Email
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="ayesha@rgstudio.com"
              className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
              Password (12+ chars, mixed case + digit)
            </label>
            <input
              type="password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Temporary strong password"
              className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
              Role
            </label>
            <select
              value={roleCode}
              onChange={(e) => setRoleCode(e.target.value as 'manager' | 'employee')}
              className="w-full px-3 py-2 text-sm rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            >
              <option value="manager">Manager</option>
              <option value="employee">Employee</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2 px-4 text-sm font-semibold rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              {submitting ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </form>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Registered User Accounts</h3>
          <button
            type="button"
            onClick={loadUsers}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>

        {loading ? (
          <div className="p-6 text-xs text-slate-500">Loading accounts...</div>
        ) : error ? (
          <div className="p-6 text-xs text-red-600 dark:text-red-400">{error}</div>
        ) : users.length === 0 ? (
          <div className="p-6 text-xs text-slate-500">No user accounts found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs text-slate-600 dark:text-slate-400">
                  <th className="py-2.5 px-4 font-semibold">Name</th>
                  <th className="py-2.5 px-4 font-semibold">Username</th>
                  <th className="py-2.5 px-4 font-semibold">Email</th>
                  <th className="py-2.5 px-4 font-semibold">Role</th>
                  <th className="py-2.5 px-4 font-semibold">Status</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="py-2.5 px-4 text-xs font-medium">{u.full_name}</td>
                    <td className="py-2.5 px-4 font-mono text-xs">{u.username}</td>
                    <td className="py-2.5 px-4 text-xs text-slate-600 dark:text-slate-300">
                      {u.email}
                    </td>
                    <td className="py-2.5 px-4 text-xs">{u.role_name}</td>
                    <td className="py-2.5 px-4 text-xs">
                      <span
                        className={
                          u.is_active
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : 'text-red-700 dark:text-red-400 font-medium'
                        }
                      >
                        {u.is_active ? 'Active' : 'Deactivated'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {u.id === currentUser.id ? (
                        <span className="text-xs text-slate-400">Current Session</span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleToggleStatus(u)}
                          className="px-2.5 py-1 text-xs font-medium rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                        >
                          {u.is_active ? 'Deactivate' : 'Activate'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
