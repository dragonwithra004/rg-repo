export type RoleCode = 'admin' | 'manager' | 'employee';

export type ConnectionState = 'Online' | 'Offline' | 'Synchronizing';

export interface UserSummary {
  id: string;
  full_name: string;
  username: string;
  email: string;
  role_code: RoleCode;
  role_name: string;
  is_active: boolean;
  theme_preference: 'dark' | 'light';
  permissions: string[];
  last_login_at: string | null;
  created_at: string;
}

export interface AuditLogEntry {
  id: string;
  actor_user_id: string | null;
  actor_username: string | null;
  action: string;
  record_type: string;
  record_id: string | null;
  details: string;
  created_at: string;
}
