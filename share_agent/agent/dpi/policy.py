from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from shared.intel import get_base_domain, is_sensitive_destination, normalize_host


DEFAULT_ALLOWED_PROCESSES = ["chrome.exe", "msedge.exe"]
DEFAULT_ALLOWED_DOMAINS = [
    "youtube.com",
    "googlevideo.com",
    "youtubei.googleapis.com",
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "search.brave.com",
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "github.com",
    "githubassets.com",
    "githubusercontent.com",
]
LEGACY_ALLOWED_DOMAINS = [
    "youtube.com",
    "googlevideo.com",
    "youtubei.googleapis.com",
    "openai.com",
    "chatgpt.com",
    "github.com",
    "githubassets.com",
    "githubusercontent.com",
]
DEFAULT_SNIPPET_MAX_BYTES = 256


def _normalize_processes(values: Optional[Iterable[str]]) -> list[str]:
    normalized: list[str] = []
    for value in values or []:
        item = str(value or "").strip().lower()
        if item and item not in normalized:
            normalized.append(item)
    return normalized


def _normalize_domains(values: Optional[Iterable[str]]) -> list[str]:
    normalized: list[str] = []
    for value in values or []:
        host = normalize_host(value)
        if not host:
            continue
        base_domain = get_base_domain(host) or host
        if base_domain not in normalized:
            normalized.append(base_domain)
    return normalized


def _resolve_allowed_domains(values: Optional[Iterable[str]]) -> list[str]:
    normalized = _normalize_domains(values)
    if not normalized:
        return list(DEFAULT_ALLOWED_DOMAINS)
    if set(normalized) == set(_normalize_domains(LEGACY_ALLOWED_DOMAINS)):
        return list(DEFAULT_ALLOWED_DOMAINS)
    return normalized


@dataclass(slots=True)
class InspectionPolicy:
    agent_id: Optional[str]
    device_ip: str
    inspection_enabled: bool = False
    allowed_processes: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_PROCESSES))
    allowed_domains: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_DOMAINS))
    snippet_max_bytes: int = DEFAULT_SNIPPET_MAX_BYTES
    privacy_guard_enabled: bool = True
    sensitive_destination_bypass_enabled: bool = True
    updated_at: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: Optional[dict], *, agent_id: Optional[str], device_ip: str) -> "InspectionPolicy":
        payload = payload or {}
        return cls(
            agent_id=payload.get("agent_id") or agent_id,
            device_ip=payload.get("device_ip") or device_ip,
            inspection_enabled=bool(payload.get("inspection_enabled")),
            allowed_processes=_normalize_processes(payload.get("allowed_processes")) or list(DEFAULT_ALLOWED_PROCESSES),
            allowed_domains=_resolve_allowed_domains(payload.get("allowed_domains")),
            snippet_max_bytes=min(
                max(int(payload.get("snippet_max_bytes") or DEFAULT_SNIPPET_MAX_BYTES), 0),
                DEFAULT_SNIPPET_MAX_BYTES,
            ),
            privacy_guard_enabled=bool(payload.get("privacy_guard_enabled", True)),
            sensitive_destination_bypass_enabled=bool(payload.get("sensitive_destination_bypass_enabled", True)),
            updated_at=payload.get("updated_at"),
        )

    def allows_process(self, process_name: Optional[str]) -> bool:
        candidate = str(process_name or "").strip().lower()
        return bool(candidate and candidate in self.allowed_processes)

    def allows_domain(self, domain: Optional[str]) -> bool:
        host = normalize_host(domain)
        if not host:
            return False
        base_domain = get_base_domain(host) or host
        if host in self.allowed_domains or base_domain in self.allowed_domains:
            return True

        for allowed in self.allowed_domains:
            if host == allowed or host.endswith(f".{allowed}"):
                return True

        return False

    def should_bypass_sensitive_destination(self, domain: Optional[str]) -> bool:
        if not self.privacy_guard_enabled or not self.sensitive_destination_bypass_enabled:
            return False
        return is_sensitive_destination(domain or "")

    def to_payload(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "device_ip": self.device_ip,
            "inspection_enabled": self.inspection_enabled,
            "allowed_processes": list(self.allowed_processes),
            "allowed_domains": list(self.allowed_domains),
            "snippet_max_bytes": self.snippet_max_bytes,
            "privacy_guard_enabled": self.privacy_guard_enabled,
            "sensitive_destination_bypass_enabled": self.sensitive_destination_bypass_enabled,
            "updated_at": self.updated_at,
        }
