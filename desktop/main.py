"""Entry point for RG Studio Management System desktop client."""

import sys
from PySide6.QtWidgets import QApplication, QDialog

from app.config import ClientConfig
from app.services.api_client import ApiClient
from app.ui.login_window import LoginWindow
from app.ui.main_window import MainWindow
from app.ui.themes import get_stylesheet


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("RG Studio Management System")

    config = ClientConfig()
    app.setStyleSheet(get_stylesheet(config.theme))

    api_client = ApiClient(config)
    api_client.start_monitoring()

    # Open directly into the Dashboard if a valid saved session exists
    if not api_client.restore_saved_session():
        login = LoginWindow(config, api_client)
        if login.exec() != QDialog.DialogCode.Accepted:
            api_client.stop_monitoring()
            return 0

    window = MainWindow(config, api_client)
    window.show()
    exit_code = app.exec()
    api_client.stop_monitoring()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
