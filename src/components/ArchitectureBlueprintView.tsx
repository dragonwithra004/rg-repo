import React, { useState } from 'react';
import {
  FOLDER_TREE_SPEC,
  PHASE1_ENDPOINTS,
  SCHEMA_TABLES,
} from '../data/phase1Architecture';

type BlueprintTab = 'structure' | 'schema' | 'api' | 'deployment';

export const ArchitectureBlueprintView: React.FC = () => {
  const [tab, setTab] = useState<BlueprintTab>('structure');

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            Phase 1 Architecture & Foundation Blueprint
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Folder structure, 20-table PostgreSQL schema, FastAPI endpoints, and external deployment setup.
          </p>
        </div>

        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md">
          {(
            [
              ['structure', 'Folder Structure'],
              ['schema', '20-Table Schema'],
              ['api', 'REST API & RBAC'],
              ['deployment', 'Services & Deployment'],
            ] as [BlueprintTab, string][]
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                tab === key
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {tab === 'structure' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5">
          <h3 className="text-sm font-semibold mb-3">
            Modular Repository Layout (Backend + PySide6 Desktop + SQL Migrations)
          </h3>
          <pre className="text-xs font-mono leading-relaxed overflow-x-auto p-4 rounded-md bg-slate-950 text-slate-200 border border-slate-800">
            {FOLDER_TREE_SPEC}
          </pre>
        </div>
      )}

      {tab === 'schema' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold">
              Normalized PostgreSQL Schema (migrations/001_initial_schema.sql)
            </h3>
            <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
              20 tables · UUID PKs · RLS enabled
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs text-slate-600 dark:text-slate-400">
                  <th className="py-2.5 px-4 font-semibold">#</th>
                  <th className="py-2.5 px-4 font-semibold">Table</th>
                  <th className="py-2.5 px-4 font-semibold">Domain</th>
                  <th className="py-2.5 px-4 font-semibold">Purpose</th>
                  <th className="py-2.5 px-4 font-semibold">Key Integrity Constraints</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {SCHEMA_TABLES.map((t) => (
                  <tr
                    key={t.name}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-2.5 px-4 font-mono tabular-nums text-xs text-slate-500">
                      {String(t.index).padStart(2, '0')}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-xs font-semibold text-blue-700 dark:text-blue-400">
                      {t.name}
                    </td>
                    <td className="py-2.5 px-4 text-xs text-slate-600 dark:text-slate-300">
                      {t.domain}
                    </td>
                    <td className="py-2.5 px-4 text-xs text-slate-700 dark:text-slate-300">
                      {t.purpose}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">
                      {t.keyConstraints}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'api' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800">
            <h3 className="text-sm font-semibold">
              Phase 1 FastAPI Endpoints (Argon2id + JWT + Server-Enforced RBAC)
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs text-slate-600 dark:text-slate-400">
                  <th className="py-2.5 px-4 font-semibold">Method</th>
                  <th className="py-2.5 px-4 font-semibold">Endpoint</th>
                  <th className="py-2.5 px-4 font-semibold">RBAC Policy</th>
                  <th className="py-2.5 px-4 font-semibold">Behavior</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {PHASE1_ENDPOINTS.map((ep) => (
                  <tr key={`${ep.method}-${ep.path}`}>
                    <td className="py-2.5 px-4 font-mono text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                      {ep.method}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-xs">{ep.path}</td>
                    <td className="py-2.5 px-4 text-xs text-slate-600 dark:text-slate-300">
                      {ep.access}
                    </td>
                    <td className="py-2.5 px-4 text-xs text-slate-700 dark:text-slate-300">
                      {ep.purpose}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'deployment' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-3">
            <h3 className="text-sm font-semibold">External Services Requiring Setup</h3>
            <ul className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
              <li>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  1. Supabase Hosted PostgreSQL:
                </strong>{' '}
                Provision project, enforce SSL, and apply{' '}
                <code className="font-mono">migrations/001_initial_schema.sql</code> or Alembic head.
              </li>
              <li>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  2. Hosted FastAPI Runtime (Railway / Render / VPS):
                </strong>{' '}
                Host <code className="font-mono">backend/</code> behind HTTPS TLS so office PCs never rely on an Admin workstation staying powered on.
              </li>
              <li>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  3. Secret Isolation:
                </strong>{' '}
                Keep <code className="font-mono">RG_DATABASE_URL</code>,{' '}
                <code className="font-mono">RG_JWT_SECRET_KEY</code>, and{' '}
                <code className="font-mono">RG_SETUP_BOOTSTRAP_TOKEN</code> strictly on the backend server.
              </li>
            </ul>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-3">
            <h3 className="text-sm font-semibold">Windows 10 Multi-Workstation Deployment</h3>
            <ul className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
              <li>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  1. Zero DB Secrets in EXE:
                </strong>{' '}
                The PySide6 desktop binary receives only{' '}
                <code className="font-mono">RG_API_BASE_URL</code>.
              </li>
              <li>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  2. PyInstaller Build:
                </strong>{' '}
                Package <code className="font-mono">desktop/main.py</code> via{' '}
                <code className="font-mono">pyinstaller desktop/build_windows.spec</code>.
              </li>
              <li>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  3. Offline Safety Policy:
                </strong>{' '}
                When offline, cached authorized views remain readable while all write operations are blocked.
              </li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
