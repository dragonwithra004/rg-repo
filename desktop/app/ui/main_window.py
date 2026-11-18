"""Main desktop shell for RG Studio Management System (Phase 1)."""

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import ClientConfig
from app.services.api_client import ApiClient, ApiError, OfflineMutationBlockedError
from app.ui.themes import get_stylesheet


class MainWindow(QMainWindow):
    def __init__(self, config: ClientConfig, api_client: ApiClient) -> None:
        super().__init__()
        self.config = config
        self.api_client = api_client
        self.user = api_client.current_user or {}
        self.role_code = str(self.user.get("role_code", "employee"))
        self.nav_buttons: dict[str, QPushButton] = {}
        self.page_indices: dict[str, int] = {}

        self.setWindowTitle("RG STUDIO MANAGEMENT SYSTEM")
        self.resize(1360, 840)

        central = QWidget()
        self.setCentralWidget(central)
        shell_layout = QHBoxLayout(central)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(256)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(16, 20, 16, 20)
        side_layout.setSpacing(6)

        brand_label = QLabel("RG STUDIO\nMANAGEMENT SYSTEM")
        brand_label.setStyleSheet("font-size: 14px; font-weight: 700; padding-bottom: 12px;")
        side_layout.addWidget(brand_label)

        self.stack = QStackedWidget()

        nav_specs = self._build_role_nav_specs()
        for key, label, phase_note in nav_specs:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _=False, k=key: self._switch_page(k))
            side_layout.addWidget(btn)
            self.nav_buttons[key] = btn

            widget = self._create_page_widget(key, label, phase_note)
            idx = self.stack.addWidget(widget)
            self.page_indices[key] = idx

        side_layout.addStretch()

        role_info = QLabel(
            f"{self.user.get('full_name', 'User')}\nRole: {self.user.get('role_name', self.role_code)}"
        )
        role_info.setStyleSheet("font-size: 12px; color: #94A3B8; padding-top: 8px;")
        side_layout.addWidget(role_info)

        logout_btn = QPushButton("Sign Out")
        logout_btn.setObjectName("SecondaryButton")
        logout_btn.clicked.connect(self._handle_logout)
        side_layout.addWidget(logout_btn)

        shell_layout.addWidget(sidebar)

        # Right column: Top Bar + Stacked Main Content
        right_col = QVBoxLayout()
        right_col.setContentsMargins(0, 0, 0, 0)
        right_col.setSpacing(0)

        top_bar = QFrame()
        top_bar.setObjectName("TopBar")
        top_bar.setFixedHeight(58)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(24, 10, 24, 10)

        self.page_title = QLabel("Dashboard")
        self.page_title.setStyleSheet("font-size: 16px; font-weight: 600;")
        top_layout.addWidget(self.page_title)
        top_layout.addStretch()

        self.conn_badge = QLabel(f"State: {self.api_client.connection_state}")
        self.conn_badge.setStyleSheet("font-weight: 600; padding-right: 12px;")
        top_layout.addWidget(self.conn_badge)

        self.theme_btn = QPushButton(
            "Switch to Light Theme" if self.config.theme == "dark" else "Switch to Dark Theme"
        )
        self.theme_btn.setObjectName("SecondaryButton")
        self.theme_btn.clicked.connect(self._toggle_theme)
        top_layout.addWidget(self.theme_btn)

        right_col.addWidget(top_bar)
        right_col.addWidget(self.stack, 1)

        shell_layout.addLayout(right_col, 1)

        self.api_client.connection_state_changed.connect(
            lambda s: self.conn_badge.setText(f"State: {s}")
        )
        self.api_client.session_expired.connect(self._handle_session_expired)

        self._switch_page("dashboard")

    def _build_role_nav_specs(self) -> list[tuple[str, str, str]]:
        if self.role_code == "admin":
            return [
                ("dashboard", "Dashboard", "Phase 1 Foundation"),
                ("infra", "Infrastructure Settings", "Permanent Config & Health"),
                ("employees", "Employees", "Scheduled for Phase 2"),
                ("mobiles", "Mobile Inventory", "Scheduled for Phase 2"),
                ("sims", "SIM Management", "Scheduled for Phase 2"),
                ("gmail", "Gmail Accounts", "Scheduled for Phase 3"),
                ("youtube", "YouTube Accounts", "Scheduled for Phase 3"),
                ("company_channels", "My Running Channels", "Scheduled for Phase 3"),
                ("assignments", "Assignments", "Scheduled for Phase 4"),
                ("reports", "Reports", "Scheduled for Phase 4"),
                ("users", "User Management", "Phase 1 Active"),
                ("audit", "Activity Logs", "Scheduled for Phase 5"),
                ("settings", "Settings & Backup", "Phase 1 Theme / Phase 5 Backup"),
            ]
        if self.role_code == "manager":
            return [
                ("dashboard", "Dashboard", "Phase 1 Foundation"),
                ("employees", "Employees", "Scheduled for Phase 2"),
                ("mobiles", "Mobile Inventory", "Scheduled for Phase 2"),
                ("sims", "SIM Management", "Scheduled for Phase 2"),
                ("gmail", "Gmail Accounts", "Scheduled for Phase 3"),
                ("youtube", "YouTube Accounts", "Scheduled for Phase 3"),
                ("company_channels", "My Running Channels", "Scheduled for Phase 3"),
                ("assignments", "Assignments", "Scheduled for Phase 4"),
                ("reports", "Team Reports", "Scheduled for Phase 4"),
                ("settings", "Settings", "Phase 1 Theme & Profile"),
            ]
        return [
            ("dashboard", "My Workspace", "Phase 1 Foundation"),
            ("my_devices", "My Assigned Devices", "Scheduled for Phase 2–4"),
            ("my_accounts", "My Accounts & Channels", "Scheduled for Phase 3–4"),
            ("requests", "Requests & Reports", "Scheduled for Phase 4"),
            ("settings", "Settings", "Phase 1 Theme & Profile"),
        ]

    def _create_page_widget(self, key: str, label: str, phase_note: str) -> QWidget:
        if key == "dashboard":
            return self._build_dashboard_page()
        if key == "infra" and self.role_code == "admin":
            return self._build_infra_page()
        if key == "users" and self.role_code == "admin":
            return self._build_users_page()
        if key == "settings":
            return self._build_settings_page()
        return self._build_phase_placeholder_page(label, phase_note)

    def _build_infra_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        card = QFrame()
        card.setObjectName("SurfaceCard")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        c_layout.setSpacing(10)

        title = QLabel("Permanent Infrastructure Settings & Startup Status")
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        c_layout.addWidget(title)

        self.infra_summary_label = QLabel(
            f"Saved FastAPI URL: {self.config.api_base_url or 'Not Configured'}\n"
            f"Connection State: {self.api_client.connection_state}"
        )
        self.infra_summary_label.setWordWrap(True)
        c_layout.addWidget(self.infra_summary_label)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("Test Backend Connection")
        refresh_btn.setObjectName("PrimaryButton")
        refresh_btn.clicked.connect(self._refresh_infra_page)
        db_btn = QPushButton("Test Database Connection")
        db_btn.setObjectName("SecondaryButton")
        db_btn.clicked.connect(self._test_infra_db)
        btn_row.addWidget(refresh_btn)
        btn_row.addWidget(db_btn)
        btn_row.addStretch()
        c_layout.addLayout(btn_row)

        layout.addWidget(card)
        layout.addStretch()
        return page

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        card = QFrame()
        card.setObjectName("SurfaceCard")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        c_layout.setSpacing(8)

        heading = QLabel("Phase 1 Desktop Shell — Authenticated Session Active")
        heading.setStyleSheet("font-size: 16px; font-weight: 700;")
        c_layout.addWidget(heading)

        details = QLabel(
            f"Signed in as: {self.user.get('full_name')} (@{self.user.get('username')})\n"
            f"Assigned Role: {self.user.get('role_name')} ({self.role_code})\n"
            f"Backend Endpoint: {self.config.api_base_url}\n"
            f"Granted Permissions: {len(self.user.get('permissions', []))}"
        )
        c_layout.addWidget(details)
        layout.addWidget(card)
        layout.addStretch()
        return page

    def _build_users_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        form_card = QFrame()
        form_card.setObjectName("SurfaceCard")
        form_layout = QFormLayout(form_card)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(10)

        self.new_full_name = QLineEdit()
        self.new_username = QLineEdit()
        self.new_email = QLineEdit()
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_role = QComboBox()
        self.new_role.addItems(["manager", "employee"])

        form_layout.addRow("Full Name", self.new_full_name)
        form_layout.addRow("Username", self.new_username)
        form_layout.addRow("Email", self.new_email)
        form_layout.addRow("Password (12+ chars)", self.new_password)
        form_layout.addRow("Role", self.new_role)

        btn_row = QHBoxLayout()
        create_btn = QPushButton("Create User Account")
        create_btn.setObjectName("PrimaryButton")
        create_btn.clicked.connect(self._create_user)
        refresh_btn = QPushButton("Refresh Directory")
        refresh_btn.setObjectName("SecondaryButton")
        refresh_btn.clicked.connect(self._load_users_table)
        btn_row.addWidget(create_btn)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()
        form_layout.addRow(btn_row)
        layout.addWidget(form_card)

        self.users_table = QTableWidget(0, 5)
        self.users_table.setHorizontalHeaderLabels(
            ["Full Name", "Username", "Email", "Role", "Status"]
        )
        self.users_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.users_table, 1)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        card = QFrame()
        card.setObjectName("SurfaceCard")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        c_layout.setSpacing(10)

        c_layout.addWidget(QLabel("Appearance & Session Settings"))
        toggle_btn = QPushButton("Toggle Dark / Light Theme")
        toggle_btn.setObjectName("PrimaryButton")
        toggle_btn.clicked.connect(self._toggle_theme)
        c_layout.addWidget(toggle_btn)

        note = QLabel(
            "Database backup configuration and restore workflows are scheduled for Phase 5."
        )
        c_layout.addWidget(note)
        layout.addWidget(card)
        layout.addStretch()
        return page

    def _build_phase_placeholder_page(self, label: str, phase_note: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        card = QFrame()
        card.setObjectName("SurfaceCard")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel(f"{label} — {phase_note}")
        title.setStyleSheet("font-size: 15px; font-weight: 600;")
        c_layout.addWidget(title)
        c_layout.addWidget(
            QLabel(
                "This module shell is wired to your role navigation and will be populated "
                "with real database workflows in the scheduled phase."
            )
        )
        layout.addWidget(card)
        layout.addStretch()
        return page

    def _switch_page(self, key: str) -> None:
        if key not in self.page_indices:
            return
        for k, btn in self.nav_buttons.items():
            btn.setProperty("active", k == key)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self.stack.setCurrentIndex(self.page_indices[key])
        self.page_title.setText(self.nav_buttons[key].text())
        if key == "users" and self.role_code == "admin":
            self._load_users_table()
        elif key == "infra" and self.role_code == "admin":
            self._refresh_infra_page()

    def _refresh_infra_page(self) -> None:
        if not hasattr(self, "infra_summary_label"):
            return
        try:
            data = self.api_client.get_infra_status()
            self.infra_summary_label.setText(
                f"Saved FastAPI URL: {self.config.api_base_url or 'Not Configured'}\n"
                f"FastAPI Backend: {self.api_client.connection_state}\n"
                f"Supabase: {'Configured' if data.get('supabase_configured') else 'Not Configured'}\n"
                f"Database Connection: {'Connected' if data.get('database_connected') else 'Disconnected'}\n"
                f"JWT Security: {'Configured' if data.get('jwt_configured') else 'Not Configured'}\n"
                f"Storage Mode: {data.get('persistent_storage_mode', 'unknown')}"
            )
        except ApiError as exc:
            self.infra_summary_label.setText(
                f"Saved FastAPI URL: {self.config.api_base_url or 'Not Configured'}\n"
                f"FastAPI Backend: {self.api_client.connection_state}\n"
                f"Note: {exc}"
            )

    def _test_infra_db(self) -> None:
        try:
            data = self.api_client.test_backend_db()
            self._refresh_infra_page()
            QMessageBox.information(
                self,
                "Database Check",
                f"Database Connected: {'Connected' if data.get('database_connected') else 'Disconnected'}",
            )
        except ApiError as exc:
            QMessageBox.warning(self, "Database Check Failed", str(exc))

    def _load_users_table(self) -> None:
        try:
            users, from_cache = self.api_client.get_users()
            self.users_table.setRowCount(len(users))
            for row_idx, item in enumerate(users):
                self.users_table.setItem(row_idx, 0, QTableWidgetItem(item["full_name"]))
                self.users_table.setItem(row_idx, 1, QTableWidgetItem(item["username"]))
                self.users_table.setItem(row_idx, 2, QTableWidgetItem(item["email"]))
                self.users_table.setItem(row_idx, 3, QTableWidgetItem(item["role_name"]))
                status_text = "Active" if item["is_active"] else "Deactivated"
                if from_cache:
                    status_text += " (Cached)"
                self.users_table.setItem(row_idx, 4, QTableWidgetItem(status_text))
        except ApiError as exc:
            QMessageBox.warning(self, "User Directory", str(exc))

    def _create_user(self) -> None:
        try:
            self.api_client.create_user(
                full_name=self.new_full_name.text().strip(),
                username=self.new_username.text().strip(),
                email=self.new_email.text().strip(),
                password=self.new_password.text(),
                role_code=self.new_role.currentText(),
            )
            self.new_full_name.clear()
            self.new_username.clear()
            self.new_email.clear()
            self.new_password.clear()
            self._load_users_table()
        except (OfflineMutationBlockedError, ApiError) as exc:
            QMessageBox.warning(self, "Cannot Create User", str(exc))

    def _toggle_theme(self) -> None:
        new_theme = "light" if self.config.theme == "dark" else "dark"
        self.config.theme = new_theme
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(get_stylesheet(new_theme))
        self.theme_btn.setText(
            "Switch to Light Theme" if new_theme == "dark" else "Switch to Dark Theme"
        )

    def _handle_session_expired(self) -> None:
        QMessageBox.warning(self, "Session Expired", "Please sign in again.")
        self._handle_logout()

    def _handle_logout(self) -> None:
        self.api_client.logout()
        self.close()
