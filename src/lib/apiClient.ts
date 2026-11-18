import { UserSummary } from '../types/auth';

export const PHASE1_API_PREFIX = '/api/v1';

export interface ApiDiagnostic {
  ok: boolean;
  targetService: string;
  endpoint: string;
  resolvedUrl: string;
  httpStatus: number | null;
  contentType: string | null;
  reason: string;
  timestamp: string;
}

export interface ApiCallResult<T> {
  ok: boolean;
  data: T | null;
  errorMessage: string | null;
  diagnostic: ApiDiagnostic;
}

export interface SetupStatusPayload {
  initialized: boolean;
  requires_admin_setup: boolean;
  service?: string;
  mode?: string;
  fastapi_configured?: boolean;
  fastapi_base_url?: string;
  fastapi_healthy?: boolean;
  overall_infra_status?: 'Online' | 'Offline' | 'Configuration Required';
}

export interface HealthPayload {
  status: string;
  service?: string;
  mode?: string;
  database: string;
  fastapi_configured?: boolean;
  fastapi_base_url?: string;
  fastapi_healthy?: boolean;
  overall_infra_status?: 'Online' | 'Offline' | 'Configuration Required';
  environment: string;
  timestamp: string;
}

export interface AuthSessionPayload {
  access_token: string;
  token_type: string;
  expires_in_seconds: number;
  user: UserSummary;
}

function resolveDisplayUrl(path: string): string {
  const fullPath = `${PHASE1_API_PREFIX}${path}`;
  if (typeof window !== 'undefined' && window.location?.origin) {
    return `${window.location.origin}${fullPath}`;
  }
  return fullPath;
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<ApiCallResult<T>> {
  const method = (options.method || 'GET').toUpperCase();
  const fullPath = `${PHASE1_API_PREFIX}${path}`;
  const resolvedUrl = resolveDisplayUrl(path);
  const timestamp = new Date().toISOString();

  const headers = new Headers(options.headers || {});
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  try {
    const response = await fetch(fullPath, {
      ...options,
      method,
      headers,
      credentials: 'same-origin',
    });

    const contentType = response.headers.get('content-type');
    const rawText = await response.text();
    let parsed: unknown = null;

    if (rawText.trim()) {
      try {
        parsed = JSON.parse(rawText);
      } catch {
        const isHtml =
          (contentType && contentType.includes('text/html')) ||
          rawText.trim().startsWith('<');
        const reason = isHtml
          ? `Server returned HTML instead of JSON (HTTP ${response.status}). The Phase 1 preview Express server may still be restarting or an upstream proxy intercepted the request.`
          : `Server returned non-JSON response (HTTP ${response.status}, Content-Type: ${contentType || 'unknown'}).`;
        return {
          ok: false,
          data: null,
          errorMessage: reason,
          diagnostic: {
            ok: false,
            targetService: 'Phase 1 Sandbox API (Preview Express Server)',
            endpoint: `${method} ${fullPath}`,
            resolvedUrl,
            httpStatus: response.status,
            contentType,
            reason,
            timestamp,
          },
        };
      }
    }

    if (!response.ok) {
      const detail =
        parsed &&
        typeof parsed === 'object' &&
        'detail' in parsed &&
        typeof (parsed as { detail?: unknown }).detail === 'string'
          ? (parsed as { detail: string }).detail
          : `Request failed with HTTP ${response.status} ${response.statusText || ''}`.trim();

      return {
        ok: false,
        data: null,
        errorMessage: detail,
        diagnostic: {
          ok: false,
          targetService: 'Phase 1 Sandbox API (Preview Express Server)',
          endpoint: `${method} ${fullPath}`,
          resolvedUrl,
          httpStatus: response.status,
          contentType,
          reason: `HTTP ${response.status}: ${detail}`,
          timestamp,
        },
      };
    }

    return {
      ok: true,
      data: parsed as T,
      errorMessage: null,
      diagnostic: {
        ok: true,
        targetService: 'Phase 1 Sandbox API (Preview Express Server)',
        endpoint: `${method} ${fullPath}`,
        resolvedUrl,
        httpStatus: response.status,
        contentType,
        reason: `HTTP ${response.status} OK`,
        timestamp,
      },
    };
  } catch (err) {
    const rawMessage = err instanceof Error ? err.message : 'Unknown network failure';
    const reason =
      rawMessage === 'Failed to fetch' || rawMessage.includes('NetworkError')
        ? 'Browser network request failed before reaching the preview server (Failed to fetch). Check if the preview session expired or the server is restarting.'
        : `Network transport error: ${rawMessage}`;
    return {
      ok: false,
      data: null,
      errorMessage: reason,
      diagnostic: {
        ok: false,
        targetService: 'Phase 1 Sandbox API (Preview Express Server)',
        endpoint: `${method} ${fullPath}`,
        resolvedUrl,
        httpStatus: null,
        contentType: null,
        reason,
        timestamp,
      },
    };
  }
}

export function fetchSandboxHealth() {
  return apiRequest<HealthPayload>('/health');
}

export function fetchSetupStatus() {
  return apiRequest<SetupStatusPayload>('/setup/status');
}

export function createFirstRunAdmin(payload: {
  full_name: string;
  username: string;
  email: string;
  password: string;
}) {
  return apiRequest<UserSummary>('/setup/admin', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function registerSandboxEmployee(payload: {
  full_name: string;
  username: string;
  email: string;
  password: string;
  remember_me: boolean;
}) {
  return apiRequest<AuthSessionPayload>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function loginSandboxAccount(payload: {
  identifier: string;
  password: string;
  remember_me: boolean;
}) {
  return apiRequest<AuthSessionPayload>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}
