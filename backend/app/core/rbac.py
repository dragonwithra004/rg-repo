"""Canonical RBAC roles and permission definitions."""

from enum import Enum


class RoleCode(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"


# Granular permission catalog seeded during first-run setup or migration
PERMISSIONS: list[tuple[str, str, str]] = [
    ("dashboard.view", "Dashboard", "View executive dashboard summary"),
    ("dashboard.view_self", "Dashboard", "View personal dashboard summary"),
    ("employees.read", "Employees", "View authorized employee directory"),
    ("employees.write", "Employees", "Create and edit employee records"),
    ("employees.deactivate", "Employees", "Deactivate employee records"),
    ("employees.read_restricted", "Employees", "View restricted personal employee fields"),
    ("mobiles.read", "Mobiles", "View mobile phone inventory"),
    ("mobiles.write", "Mobiles", "Register and update mobile inventory"),
    ("sims.read", "SIM Cards", "View SIM card records"),
    ("sims.write", "SIM Cards", "Manage SIM card records"),
    ("gmail.read", "Gmail Accounts", "View Gmail account inventory"),
    ("gmail.write", "Gmail Accounts", "Manage Gmail account records"),
    ("youtube.read", "YouTube Accounts", "View employee-managed YouTube channels"),
    ("youtube.write", "YouTube Accounts", "Manage employee-managed YouTube channels"),
    ("company_channels.read", "My Running Channels", "View company-operated YouTube channels"),
    ("company_channels.write", "My Running Channels", "Manage company-operated YouTube channels"),
    ("assignments.read", "Assignments", "View assignment records and history"),
    ("assignments.write", "Assignments", "Assign, transfer, and approve returns"),
    ("self.read", "Self Service", "View own profile and assigned assets"),
    ("self.request", "Self Service", "Submit damage reports, returns, and profile updates"),
    ("reports.read", "Reports", "View authorized operational reports"),
    ("reports.export", "Reports", "Export authorized reports to PDF/Excel/CSV"),
    ("users.manage", "User Management", "Create and manage Manager and Employee accounts"),
    ("roles.manage", "User Management", "Configure role permissions"),
    ("audit.read", "Activity Logs", "View protected system audit trails"),
    ("settings.manage", "Settings", "Manage global application and security settings"),
    ("backups.manage", "Backups", "Configure backups and execute restore workflows"),
]

ROLE_PERMISSION_MAP: dict[RoleCode, list[str]] = {
    RoleCode.ADMIN: [code for code, _, _ in PERMISSIONS],
    RoleCode.MANAGER: [
        "dashboard.view",
        "employees.read",
        "employees.write",
        "mobiles.read",
        "mobiles.write",
        "sims.read",
        "sims.write",
        "gmail.read",
        "gmail.write",
        "youtube.read",
        "youtube.write",
        "company_channels.read",
        "assignments.read",
        "assignments.write",
        "reports.read",
        "reports.export",
    ],
    RoleCode.EMPLOYEE: [
        "dashboard.view_self",
        "self.read",
        "self.request",
    ],
}
