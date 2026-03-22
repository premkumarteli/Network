from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Optional
import ipaddress
import logging

try:
    import geoip2.database
except ImportError:  # pragma: no cover - exercised indirectly in tests/runtime
    geoip2 = None

from ..core.config import settings

logger = logging.getLogger("netvisor.apps.asn")


ASN_ORGANIZATION_RULES: tuple[tuple[str, str], ...] = (
    ("openai", "ChatGPT"),
    ("github", "GitHub"),
    ("meta", "Meta"),
    ("facebook", "Meta"),
    ("whatsapp", "Meta"),
    ("instagram", "Meta"),
    ("microsoft", "Microsoft"),
    ("amazon", "AWS"),
    ("google", "Google"),
)


class ASNLookupService:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = Path(db_path or settings.GEOIP_ASN_DB_PATH)
        self._reader: Any | None = None
        self._disabled = False

    def _get_reader(self) -> Any | None:
        if self._disabled:
            return None
        if self._reader is not None:
            return self._reader
        if geoip2 is None:
            self._disabled = True
            logger.info("geoip2 dependency is not installed. ASN fallback disabled.")
            return None
        if not self.db_path.exists():
            self._disabled = True
            logger.info("ASN database not found at %s. ASN fallback disabled.", self.db_path)
            return None

        try:
            self._reader = geoip2.database.Reader(str(self.db_path))
            return self._reader
        except Exception as exc:
            self._disabled = True
            logger.warning("Failed to initialize ASN database %s: %s", self.db_path, exc)
            return None

    @lru_cache(maxsize=8192)
    def lookup_organization(self, ip_value: str | None) -> Optional[str]:
        if not ip_value:
            return None
        try:
            ipaddress.ip_address(ip_value)
        except ValueError:
            return None

        reader = self._get_reader()
        if reader is None:
            return None

        try:
            result = reader.asn(ip_value)
        except Exception:
            return None

        org = (result.autonomous_system_organization or "").strip()
        return org or None

    def classify_ip(self, ip_value: str | None) -> Optional[str]:
        org = self.lookup_organization(ip_value)
        if not org:
            return None

        org_value = org.lower()
        for token, mapped_value in ASN_ORGANIZATION_RULES:
            if token in org_value:
                return mapped_value
        return None


asn_lookup_service = ASNLookupService()
