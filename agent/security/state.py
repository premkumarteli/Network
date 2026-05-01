from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .dpapi import DataProtector, WindowsCurrentUserProtector

logger = logging.getLogger(__name__)


class ProtectedStateStore:
    def __init__(
        self,
        path: Path,
        *,
        protector: DataProtector | None = None,
        description: str = "netvisor-agent-state",
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.protector = protector or WindowsCurrentUserProtector()
        self.description = description

    def load(self, default: dict | None = None) -> dict:
        default_value = dict(default or {})
        if not self.path.exists():
            return default_value
        try:
            payload = self.protector.unprotect(self.path.read_bytes())
        except Exception as exc:
            logger.warning("Protected state at %s could not be decrypted; resetting local state: %s", self.path, exc)
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
            return default_value
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
        protected = self.protector.protect(serialized, description=self.description)
        self.path.write_bytes(protected)
