"""First-run initial Administrator account setup dialog (zero hardcoded passwords)."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from app.services.api_client import ApiClient, ApiError


class FirstRunSetupDialog(QDialog):
    def __init__(self, api_client: ApiClient, parent=None) -> None:
        super().__init__(parent)
        self.api_client = api_client
        self.created_username: str | None = None

        self.setWindowTitle("RG Studio Management System — First-Run Admin Setup")
        self.setMinimumWidth(460)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Initialize Primary Administrator")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        layout.addWidget(title)

        subtitle = QLabel(
            "No Administrator account exists in the database yet. Create the initial "
            "Admin credentials below. Passwords require 12+ characters with uppercase, "
            "lowercase, and numeric digits."
        )
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        form = QFormLayout()
        form.setSpacing(10)

        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText("e.g., Tariq Mahmood")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("e.g., admin.tariq")

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("admin@rgstudio.com")

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Minimum 12 characters")

        self.setup_token_input = QLineEdit()
        self.setup_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.setup_token_input.setPlaceholderText("Required only if RG_SETUP_BOOTSTRAP_TOKEN is set")

        form.addRow("Full Name", self.full_name_input)
        form.addRow("Username", self.username_input)
        form.addRow("Email", self.email_input)
        form.addRow("Password", self.password_input)
        form.addRow("Bootstrap Token", self.setup_token_input)
        layout.addLayout(form)

        self.submit_btn = QPushButton("Create Administrator Account")
        self.submit_btn.setObjectName("PrimaryButton")
        self.submit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit_btn.clicked.connect(self._handle_submit)
        layout.addWidget(self.submit_btn)

    def _handle_submit(self) -> None:
        full_name = self.full_name_input.text().strip()
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text()
        token = self.setup_token_input.text().strip() or None

        if not full_name or not username or not email or len(password) < 12:
            QMessageBox.warning(
                self,
                "Validation Error",
                "All fields are required and password must be at least 12 characters.",
            )
            return

        self.submit_btn.setEnabled(False)
        try:
            created = self.api_client.bootstrap_admin(
                full_name=full_name,
                username=username,
                email=email,
                password=password,
                setup_token=token,
            )
            self.created_username = created["username"]
            QMessageBox.information(
                self,
                "Setup Complete",
                f"Administrator '{self.created_username}' created. You can now sign in.",
            )
            self.accept()
        except ApiError as exc:
            QMessageBox.critical(self, "Setup Failed", str(exc))
        finally:
            self.submit_btn.setEnabled(True)
