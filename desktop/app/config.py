"""Client-side permanent non-secret desktop settings (zero DB credentials or JWT secrets)."""

import json
import os
from pathlib import Path
from typing import Any
from PySide6.QtCore import QSettings


class ClientConfig:
    ORG_NAME = "RGStudio"
    APP_NAME = "RGStudioManagementSystem"
    # Intentionally blank until the FastAPI backend URL is configured by the operator
    DEFAULT_API_URL = os.getenv("RG_API_BASE_URL", "").strip()

    def __init__(self) -> None:
        self._settings = QSettings(self.ORG_NAME, self.APP_NAME)
        self._config_dir = Path.home() / ".rgstudio"
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._profile_path = self._config_dir / "client_settings.json"
        self._hydrate_from_disk_if_needed()

    def _read_disk_profile(self) -> dict[str, Any]:
        if not self._profile_path.exists():
            return {}
        try:
            data = json.loads(self._profile_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_disk_profile(self, updates: dict[str, Any]) -> None:
        current = self._read_disk_profile()
        # Never persist secrets or passwords in client settings
        sanitized = {
            k: v
            for k, v in {**current, **updates}.items()
            if k in {"api_base_url", "theme", "remember_session"}
        }
        self._profile_path.write_text(json.dumps(sanitized, indent=2), encoding="utf-8")

    def _hydrate_from_disk_if_needed(self) -> None:
        disk = self._read_disk_profile()
        q_url = str(self._settings.value("network/api_base_url", "")).strip()
        disk_url = str(disk.get("api_base_url", "")).strip()
        if not q_url and disk_url:
            self._settings.setValue("network/api_base_url", disk_url.rstrip("/"))
        elif q_url and not disk_url:
            self._write_disk_profile({"api_base_url": q_url.rstrip("/")})

    @property
    def api_base_url(self) -> str:
        raw = str(self._settings.value("network/api_base_url", self.DEFAULT_API_URL)).strip()
        if not raw:
            raw = str(self._read_disk_profile().get("api_base_url", "")).strip()
        return raw.rstrip("/")

    @api_base_url.setter
    def api_base_url(self, value: str) -> None:
        cleaned = value.strip().rstrip("/")
        self._settings.setValue("network/api_base_url", cleaned)
        self._write_disk_profile({"api_base_url": cleaned})

    @property
    def is_api_configured(self) -> bool:
        url = self.api_base_url
        return url.startswith("https://") or url.startswith("http://")

    @property
    def theme(self) -> str:
        val = str(self._settings.value("ui/theme", "dark")).lower()
        return val if val in {"dark", "light"} else "dark"

    @theme.setter
    def theme(self, value: str) -> None:
        if value in {"dark", "light"}:
            self._settings.setValue("ui/theme", value)
            self._write_disk_profile({"theme": value})

    @property
    def remember_session(self) -> bool:
        return str(self._settings.value("auth/remember_session", "true")).lower() == "true"

    @remember_session.setter
    def remember_session(self, value: bool) -> None:
        self._settings.setValue("auth/remember_session", "true" if value else "false")
        self._write_disk_profile({"remember_session": bool(value)})

    def save_session(self, refresh_token: str, user: dict[str, Any]) -> None:
        self._settings.setValue("auth/refresh_token", refresh_token)
        self._settings.setValue("auth/cached_user_json", json.dumps(user))

    def load_saved_session(self) -> tuple[str | None, dict[str, Any] | None]:
        if not self.remember_session:
            return None, None
        token = str(self._settings.value("auth/refresh_token", "")).strip() or None
        raw_user = str(self._settings.value("auth/cached_user_json", "")).strip()
        user: dict[str, Any] | None = None
        if raw_user:
            try:
                user = json.loads(raw_user)
            except json.JSONDecodeError:
                user = None
        return token, user

    def clear_saved_session(self) -> None:
        self._settings.remove("auth/refresh_token")
        self._settings.remove("auth/cached_user_json")
