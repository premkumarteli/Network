from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from app.utils.domain_utils import get_base_domain, normalize_host


DEFAULT_ALLOWED_PROCESSES = ["chrome.exe", "msedge.exe", "firefox.exe", "python.exe"]
DEFAULT_ALLOWED_DOMAINS = [
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "yahoo.com",
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


@dataclass(slots=True)
class InspectionPolicy:
    agent_id: Optional[str]
    device_ip: str
    inspection_enabled: bool = False
    allowed_processes: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_PROCESSES))
    allowed_domains: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_DOMAINS))
    snippet_max_bytes: int = DEFAULT_SNIPPET_MAX_BYTES
    updated_at: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: Optional[dict], *, agent_id: Optional[str], device_ip: str) -> "InspectionPolicy":
        payload = payload or {}
        return cls(
            agent_id=payload.get("agent_id") or agent_id,
            device_ip=payload.get("device_ip") or device_ip,
            inspection_enabled=bool(payload.get("inspection_enabled")),
            allowed_processes=_normalize_processes(payload.get("allowed_processes")) or list(DEFAULT_ALLOWED_PROCESSES),
            allowed_domains=_normalize_domains(payload.get("allowed_domains")) or list(DEFAULT_ALLOWED_DOMAINS),
            snippet_max_bytes=min(
                max(int(payload.get("snippet_max_bytes") or DEFAULT_SNIPPET_MAX_BYTES), 0),
                DEFAULT_SNIPPET_MAX_BYTES,
            ),
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
        
        # Exact match on base domain
        if base_domain in self.allowed_domains:
            return True
            
        # Suffix matching for regional variants (e.g. google.co.in match google.com)
        # Simplified: if any allowed domain is in the host
        for allowed in self.allowed_domains:
            if allowed in host:
                return True
                
        return False

    def to_payload(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "device_ip": self.device_ip,
            "inspection_enabled": self.inspection_enabled,
            "allowed_processes": list(self.allowed_processes),
            "allowed_domains": list(self.allowed_domains),
            "snippet_max_bytes": self.snippet_max_bytes,
            "updated_at": self.updated_at,
        }
