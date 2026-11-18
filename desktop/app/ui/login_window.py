"""Login window (default home gate) + Sign Up navigation for RG Studio desktop client."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from app.config import ClientConfig
from app.services.api_client import ApiClient, ApiError
from app.ui.first_run_dialog import FirstRunSetupDialog


class RegisterDialog(QDialog):
    """Employee self-registration dialog when system already has an Administrator."""

    def __init__(self, api_client: ApiClient, remember: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.api_client = api_client
        self.remember = remember
        self.session_data: dict | None = None

        self.setWindowTitle("RG Studio Management System — Create Account")
        self.setMinimumWidth(440)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Create Employee Account")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)
        self.full_name_input = QLineEdit()
        self.username_input = QLineEdit()
        self.email_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("12+ chars, upper, lower, digit")

        form.addRow("Full Name", self.full_name_input)
        form.addRow("Username", self.username_input)
        form.addRow("Email", self.email_input)
        form.addRow("Password", self.password_input)
        layout.addLayout(form)

        self.submit_btn = QPushButton("Sign Up & Open Dashboard")
        self.submit_btn.setObjectName("PrimaryButton")
        self.submit_btn.clicked.connect(self._handle_register)
        layout.addWidget(self.submit_btn)

    def _handle_register(self) -> None:
        self.submit_btn.setEnabled(False)
        try:
            self.session_data = self.api_client.register_employee(
                full_name=self.full_name_input.text().strip(),
                username=self.username_input.text().strip(),
                email=self.email_input.text().strip(),
                password=self.password_input.text(),
                remember=self.remember,
            )
            self.accept()
        except ApiError as exc:
            QMessageBox.critical(self, "Sign Up Failed", str(exc))
        finally:
            self.submit_btn.setEnabled(True)


class LoginWindow(QDialog):
    authenticated = Signal(dict)

    def __init__(self, config: ClientConfig, api_client: ApiClient, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self.api_client = api_client

        self.setWindowTitle("RG STUDIO MANAGEMENT SYSTEM — Sign In")
        self.setFixedSize(460, 520)

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)

        brand = QLabel("RG STUDIO MANAGEMENT SYSTEM")
        brand.setStyleSheet("font-size: 16px; font-weight: 700; letter-spacing: 0.4px;")
        root.addWidget(brand)

        subtitle = QLabel("Sign in with your assigned Admin, Manager, or Employee account.")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        card = QFrame()
        card.setObjectName("SurfaceCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(12)

        card_layout.addWidget(QLabel("Email or Username"))
        self.identifier_input = QLineEdit()
        self.identifier_input.setPlaceholderText("username or name@rgstudio.com")
        card_layout.addWidget(self.identifier_input)

        card_layout.addWidget(QLabel("Password"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.returnPressed.connect(self._handle_login)
        card_layout.addWidget(self.password_input)

        self.api_url_label = QLabel("Backend API URL (saved permanently after first setup)")
        self.api_url_input = QLineEdit(self.config.api_base_url)
        self.api_url_input.setPlaceholderText("Enter deployed FastAPI HTTPS URL (e.g., https://...)")

        self.saved_server_row = QHBoxLayout()
        self.saved_server_label = QLabel(
            f"Server: {self.config.api_base_url}" if self.config.is_api_configured else ""
        )
        self.saved_server_label.setStyleSheet("font-size: 11px; color: #94A3B8;")
        self.change_server_btn = QPushButton("Change")
        self.change_server_btn.setObjectName("SecondaryButton")
        self.change_server_btn.clicked.connect(self._toggle_server_editor)
        self.saved_server_row.addWidget(self.saved_server_label, 1)
        self.saved_server_row.addWidget(self.change_server_btn)

        card_layout.addLayout(self.saved_server_row)
        card_layout.addWidget(self.api_url_label)
        card_layout.addWidget(self.api_url_input)

        if self.config.is_api_configured:
            self.api_url_label.hide()
            self.api_url_input.hide()
        else:
            self.saved_server_label.hide()
            self.change_server_btn.hide()

        self.remember_checkbox = QCheckBox("Keep me signed in (open dashboard automatically)")
        self.remember_checkbox.setChecked(True)
        card_layout.addWidget(self.remember_checkbox)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("color: #EF4444;")
        card_layout.addWidget(self.status_label)

        self.login_btn = QPushButton("Sign In")
        self.login_btn.setObjectName("PrimaryButton")
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self._handle_login)
        card_layout.addWidget(self.login_btn)

        root.addWidget(card)

        footer = QHBoxLayout()
        self.connection_label = QLabel(f"Server: {self.api_client.connection_state}")
        footer.addWidget(self.connection_label)
        footer.addStretch()

        self.signup_btn = QPushButton("Create Account (Sign Up)")
        self.signup_btn.setObjectName("SecondaryButton")
        self.signup_btn.clicked.connect(self._open_signup_flow)
        footer.addWidget(self.signup_btn)
        root.addLayout(footer)

        self.api_client.connection_state_changed.connect(
            lambda state: self.connection_label.setText(f"Server: {state}")
        )

    def _toggle_server_editor(self) -> None:
        self.api_url_label.show()
        self.api_url_input.show()
        self.saved_server_label.hide()
        self.change_server_btn.hide()

    def _save_api_url_if_changed(self) -> None:
        entered = self.api_url_input.text().strip()
        if entered:
            self.config.api_base_url = entered
            self.api_client.check_health()

    def _open_signup_flow(self) -> None:
        self._save_api_url_if_changed()
        try:
            status_data = self.api_client.get_setup_status()
            if status_data.get("requires_admin_setup"):
                dlg = FirstRunSetupDialog(self.api_client, self)
                if dlg.exec() == QDialog.DialogCode.Accepted and dlg.created_username:
                    self.identifier_input.setText(dlg.created_username)
                return

            reg = RegisterDialog(
                self.api_client,
                remember=self.remember_checkbox.isChecked(),
                parent=self,
            )
            if reg.exec() == QDialog.DialogCode.Accepted and reg.session_data:
                self.authenticated.emit(reg.session_data)
                self.accept()
        except ApiError as exc:
            self.status_label.setText(str(exc))

    def _handle_login(self) -> None:
        self._save_api_url_if_changed()
        identifier = self.identifier_input.text().strip()
        password = self.password_input.text()
        if not identifier or not password:
            self.status_label.setText("Enter both username/email and password.")
            return

        self.status_label.setText("")
        self.login_btn.setEnabled(False)
        try:
            session_data = self.api_client.login(
                identifier,
                password,
                remember=self.remember_checkbox.isChecked(),
            )
            self.authenticated.emit(session_data)
            self.accept()
        except ApiError as exc:
            self.status_label.setText(str(exc))
        finally:
            self.login_btn.setEnabled(True)
