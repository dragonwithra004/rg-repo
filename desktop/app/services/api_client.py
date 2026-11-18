"""Centralized HTTPS REST client with connection state tracking and safe read-only offline cache."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

import httpx
from PySide6.QtCore import QObject, QTimer, Signal

from app.config import ClientConfig


class OfflineMutationBlockedError(RuntimeError):
    """Raised when a user attempts to modify data while the client is Offline."""


class ApiError(RuntimeError):
    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class OfflineReadCache:
    """Read-only local SQLite cache of authorized responses for Offline viewing."""

    def __init__(self) -> None:
        cache_dir = Path.home() / ".rgstudio"
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / "authorized_cache.db"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def set_entry(self, cache_key: str, user_id: str, data: Any) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO cache_entries (cache_key, user_id, payload_json, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(cache_key) DO UPDATE SET
                    user_id = excluded.user_id,
                    payload_json = excluded.payload_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (cache_key, user_id, json.dumps(data)),
            )

    def get_entry(self, cache_key: str, user_id: str) -> Any | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT payload_json FROM cache_entries WHERE cache_key = ? AND user_id = ?",
                (cache_key, user_id),
            ).fetchone()
            return json.loads(row[0]) if row else None

    def clear_user_cache(self, user_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM cache_entries WHERE user_id = ?", (user_id,))


class ApiClient(QObject):
    connection_state_changed = Signal(str)  # "Online" | "Offline" | "Synchronizing" | "Configuration Required"
    session_expired = Signal()

    def __init__(self, config: ClientConfig) -> None:
        super().__init__()
        self.config = config
        self.cache = OfflineReadCache()
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.current_user: dict[str, Any] | None = None
        self.connection_state: str = (
            "Offline" if config.is_api_configured else "Configuration Required"
        )

        self._http = httpx.Client(timeout=10.0)
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(15000)
        self._health_timer.timeout.connect(self.check_health)

    def startup_restore(self) -> str:
        """Load permanent backend URL and validate health on startup without wiping saved settings."""
        if not self.config.is_api_configured:
            self._set_connection_state("Configuration Required")
            return self.connection_state
        self.check_health()
        return self.connection_state

    def start_monitoring(self) -> None:
        self.startup_restore()
        self._health_timer.start()

    def stop_monitoring(self) -> None:
        self._health_timer.stop()

    def _set_connection_state(self, state: str) -> None:
        if state != self.connection_state:
            self.connection_state = state
            self.connection_state_changed.emit(state)

    def _url(self, path: str) -> str:
        if not self.config.is_api_configured:
            self._set_connection_state("Configuration Required")
            raise ApiError(
                "Backend API URL is not configured yet. Enter your deployed FastAPI HTTPS URL."
            )
        return f"{self.config.api_base_url}/api/v1{path}"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    def check_health(self) -> bool:
        if not self.config.is_api_configured:
            self._set_connection_state("Configuration Required")
            return False
        try:
            resp = self._http.get(self._url("/health"))
            if resp.status_code == 200 and resp.json().get("status") == "online":
                self._set_connection_state("Online")
                return True
        except (httpx.HTTPError, ApiError):
            pass
        self._set_connection_state("Offline")
        return False

    def get_infra_status(self) -> dict[str, Any]:
        try:
            resp = self._http.get(self._url("/admin/infra/status"), headers=self._headers())
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Unable to fetch infrastructure status"), resp.status_code)
            self._set_connection_state("Online")
            return resp.json()
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise ApiError("FastAPI backend unreachable.") from exc

    def test_backend_db(self) -> dict[str, Any]:
        try:
            resp = self._http.post(self._url("/admin/infra/test-db"), headers=self._headers())
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Database test failed"), resp.status_code)
            self._set_connection_state("Online")
            return resp.json()
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise ApiError("FastAPI backend unreachable during database test.") from exc

    def get_setup_status(self) -> dict[str, Any]:
        try:
            resp = self._http.get(self._url("/setup/status"))
            self._set_connection_state("Online")
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Setup check failed"), resp.status_code)
            return resp.json()
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise ApiError("Cannot reach RG Studio backend server.") from exc

    def bootstrap_admin(
        self, full_name: str, username: str, email: str, password: str, setup_token: str | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "full_name": full_name,
            "username": username,
            "email": email,
            "password": password,
        }
        if setup_token:
            payload["setup_token"] = setup_token
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.post(self._url("/setup/admin"), json=payload)
            self._set_connection_state("Online")
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Admin setup failed"), resp.status_code)
            return resp.json()
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise ApiError("Network error while creating initial Administrator.") from exc

    def register_employee(
        self, full_name: str, username: str, email: str, password: str, remember: bool = True
    ) -> dict[str, Any]:
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.post(
                self._url("/auth/register"),
                json={
                    "full_name": full_name,
                    "username": username,
                    "email": email,
                    "password": password,
                },
            )
            self._set_connection_state("Online")
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Registration failed"), resp.status_code)
            data = resp.json()
            self._apply_session_payload(data, remember)
            return data
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise ApiError("Server unreachable. Connect to network to register.") from exc

    def _apply_session_payload(self, data: dict[str, Any], remember: bool) -> None:
        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]
        self.current_user = data["user"]
        self.cache.set_entry("profile", self.current_user["id"], self.current_user)
        self.config.remember_session = remember
        if remember:
            self.config.save_session(self.refresh_token, self.current_user)
        else:
            self.config.clear_saved_session()

    def login(self, identifier: str, password: str, remember: bool = True) -> dict[str, Any]:
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.post(
                self._url("/auth/login"),
                json={"identifier": identifier, "password": password},
            )
            self._set_connection_state("Online")
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Authentication failed"), resp.status_code)
            data = resp.json()
            self._apply_session_payload(data, remember)
            return data
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise ApiError("Server unreachable. Connect to network to authenticate.") from exc

    def restore_saved_session(self) -> bool:
        """Restore saved session on startup so returning users open straight into Dashboard."""
        saved_refresh, saved_user = self.config.load_saved_session()
        if not saved_refresh:
            return False
        if not self.config.is_api_configured:
            if saved_user:
                self.current_user = saved_user
                self._set_connection_state("Offline")
                return True
            return False
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.post(
                self._url("/auth/refresh"),
                json={"refresh_token": saved_refresh},
            )
            if resp.status_code == 200:
                data = resp.json()
                self._apply_session_payload(data, True)
                self._set_connection_state("Online")
                return True
            if resp.status_code in (401, 403):
                self.config.clear_saved_session()
                return False
        except (httpx.HTTPError, ApiError):
            if saved_user:
                self.current_user = saved_user
                self._set_connection_state("Offline")
                return True
        return False

    def logout(self) -> None:
        user_id = self.current_user["id"] if self.current_user else None
        try:
            if self.access_token and self.config.is_api_configured:
                self._http.post(self._url("/auth/logout"), headers=self._headers())
        except (httpx.HTTPError, ApiError):
            pass
        finally:
            if user_id:
                self.cache.clear_user_cache(user_id)
            self.config.clear_saved_session()
            self.access_token = None
            self.refresh_token = None
            self.current_user = None

    def get_users(self) -> tuple[list[dict[str, Any]], bool]:
        """Return (users, from_offline_cache). Only authorized for Admin."""
        user_id = self.current_user["id"] if self.current_user else ""
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.get(self._url("/users"), headers=self._headers())
            self._set_connection_state("Online")
            if resp.status_code == 401:
                self.session_expired.emit()
                raise ApiError("Session expired", 401)
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Unable to load users"), resp.status_code)
            data = resp.json()
            self.cache.set_entry("users_list", user_id, data)
            return data, False
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            cached = self.cache.get_entry("users_list", user_id)
            if cached is not None:
                return cached, True
            raise ApiError("Offline and no cached user directory available.") from exc

    def create_user(
        self, full_name: str, username: str, email: str, password: str, role_code: str
    ) -> dict[str, Any]:
        if self.connection_state == "Offline":
            raise OfflineMutationBlockedError(
                "Offline mode is read-only. Creating user accounts requires an Online connection."
            )
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.post(
                self._url("/users"),
                headers=self._headers(),
                json={
                    "full_name": full_name,
                    "username": username,
                    "email": email,
                    "password": password,
                    "role_code": role_code,
                },
            )
            self._set_connection_state("Online")
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "User creation failed"), resp.status_code)
            return resp.json()
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise OfflineMutationBlockedError(
                "Connection lost. User creation aborted to keep data consistent."
            ) from exc

    def set_user_active(self, target_user_id: str, is_active: bool) -> dict[str, Any]:
        if self.connection_state == "Offline":
            raise OfflineMutationBlockedError(
                "Offline mode is read-only. Account changes require an Online connection."
            )
        try:
            self._set_connection_state("Synchronizing")
            resp = self._http.patch(
                self._url(f"/users/{target_user_id}/status"),
                headers=self._headers(),
                json={"is_active": is_active},
            )
            self._set_connection_state("Online")
            if resp.status_code >= 400:
                raise ApiError(resp.json().get("detail", "Status update failed"), resp.status_code)
            return resp.json()
        except httpx.HTTPError as exc:
            self._set_connection_state("Offline")
            raise OfflineMutationBlockedError("Connection lost during update.") from exc
