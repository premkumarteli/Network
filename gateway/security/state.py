from __future__ import annotations

import json
import os
import logging
import stat
from pathlib import Path
from typing import Any

from .dpapi import DataProtector, WindowsCurrentUserProtector

logger = logging.getLogger(__name__)


class GatewayStateStore:
    def __init__(
        self,
        path: Path,
        *,
        protector: DataProtector | None = None,
        description: str = "netvisor-gateway-state",
        platform_name: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.platform_name = platform_name or os.name
        self.description = description
        self.protector = protector or (WindowsCurrentUserProtector() if self._is_windows() else None)

    def _is_windows(self) -> bool:
        return self.platform_name == "nt"

    def _chmod_path(self, path: Path, mode: int) -> None:
        path.chmod(mode)

    def _stat_mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def _ensure_secure_directory(self) -> None:
        if self._is_windows():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._chmod_path(self.path.parent, 0o700)
        except OSError as exc:
            raise RuntimeError(f"Unable to secure gateway state directory '{self.path.parent}': {exc}") from exc

        mode = self._stat_mode(self.path.parent)
        if mode & 0o077:
            raise RuntimeError(
                f"Gateway state directory '{self.path.parent}' must be owner-only (0700); current mode is {oct(mode)}."
            )

    def _ensure_secure_file(self) -> None:
        if self._is_windows() or not self.path.exists():
            return
        try:
            self._chmod_path(self.path, 0o600)
        except OSError as exc:
            raise RuntimeError(f"Unable to secure gateway state file '{self.path}': {exc}") from exc

        mode = self._stat_mode(self.path)
        if mode & 0o077:
            raise RuntimeError(
                f"Gateway state file '{self.path}' must be owner-only (0600); current mode is {oct(mode)}."
            )

    def load(self, default: dict | None = None) -> dict:
        default_value = dict(default or {})
        if self._is_windows():
            if not self.path.exists():
                return default_value
            try:
                payload = self.protector.unprotect(self.path.read_bytes()) if self.protector else self.path.read_bytes()
            except Exception as exc:
                logger.warning("Gateway state at %s could not be decrypted; resetting local state: %s", self.path, exc)
                try:
                    self.path.unlink(missing_ok=True)
                except OSError:
                    pass
                return default_value
        else:
            self._ensure_secure_directory()
            if not self.path.exists():
                return default_value
            self._ensure_secure_file()
            payload = self.path.read_bytes()

        try:
            loaded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
            return default_value
        return loaded if isinstance(loaded, dict) else default_value

    def save(self, value: dict[str, Any]) -> None:
        serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if self._is_windows():
            payload = self.protector.protect(serialized, description=self.description) if self.protector else serialized
            self.path.write_bytes(payload)
            return

        self._ensure_secure_directory()
        self.path.write_bytes(serialized)
        self._ensure_secure_file()
