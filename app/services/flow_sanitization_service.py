from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha1
from typing import Any, Optional

from ..utils.network import classify_ip_scope, is_unicast_mac, normalize_ip, normalize_mac


@dataclass(frozen=True)
class SanitizedFlow:
    organization_id: Optional[str]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int
    duration: float
    average_packet_size: float
    domain: Optional[str]
    sni: Optional[str]
    agent_id: str
    source_type: str
    metadata_only: bool
    src_mac: Optional[str]
    dst_mac: Optional[str]
    internal_device_ip: Optional[str]
    internal_device_mac: Optional[str]
    external_endpoint_ip: Optional[str]
    network_scope: str

    @property
    def ingest_hash(self) -> str:
        payload = (
            self.organization_id or "-",
            self.src_ip,
            self.dst_ip,
            str(self.src_port),
            str(self.dst_port),
            self.protocol,
            self.start_time.isoformat(),
            self.last_seen.isoformat(),
            str(self.packet_count),
            str(self.byte_count),
        )
        return sha1("|".join(payload).encode("utf-8")).hexdigest()


class FlowSanitizationService:
    CONTROL_SCOPES = {"invalid", "control"}

    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None

    def _normalize_host(self, value: Any) -> Optional[str]:
        if not value:
            return None
        host = str(value).strip().lower().rstrip(".")
        if not host or " " in host:
            return None
        return host

    def _resolve_scope(self, src_scope: str, dst_scope: str) -> str:
        if src_scope == "internal" and dst_scope == "internal":
            return "internal_lan"
        if src_scope == "internal" and dst_scope == "external":
            return "egress"
        if src_scope == "external" and dst_scope == "internal":
            return "ingress"
        if src_scope == "external" and dst_scope == "external":
            return "external_only"
        return "unknown"

    def sanitize_flow(self, flow: Any, *, organization_id: Optional[str]) -> Optional[SanitizedFlow]:
        src_ip = normalize_ip(getattr(flow, "src_ip", None))
        dst_ip = normalize_ip(getattr(flow, "dst_ip", None))
        if not src_ip or not dst_ip:
            return None

        src_scope = classify_ip_scope(src_ip)
        dst_scope = classify_ip_scope(dst_ip)
        if src_scope in self.CONTROL_SCOPES or dst_scope in self.CONTROL_SCOPES:
            return None

        packet_count = int(getattr(flow, "packet_count", 0) or 0)
        byte_count = int(getattr(flow, "byte_count", 0) or 0)
        if packet_count <= 0 or byte_count < 0:
            return None

        start_time = self._parse_timestamp(getattr(flow, "start_time", None))
        last_seen = self._parse_timestamp(getattr(flow, "last_seen", None))
        if not start_time or not last_seen:
            return None
        if last_seen < start_time:
            start_time = last_seen

        protocol = str(getattr(flow, "protocol", "") or "").upper().strip()
        if not protocol:
            return None

        src_mac = normalize_mac(getattr(flow, "src_mac", None))
        dst_mac = normalize_mac(getattr(flow, "dst_mac", None))
        if src_mac and not is_unicast_mac(src_mac):
            src_mac = None
        if dst_mac and not is_unicast_mac(dst_mac):
            dst_mac = None

        internal_ip = None
        internal_mac = None
        external_ip = None

        if src_scope == "internal" and dst_scope == "external":
            internal_ip = src_ip
            internal_mac = src_mac
            external_ip = dst_ip
        elif src_scope == "external" and dst_scope == "internal":
            internal_ip = dst_ip
            internal_mac = dst_mac
            external_ip = src_ip
        elif src_scope == "internal" and dst_scope == "internal":
            internal_ip = src_ip
            internal_mac = src_mac
        elif src_scope == "external" and dst_scope == "external":
            external_ip = dst_ip

        duration = max(float(getattr(flow, "duration", 0) or 0), 0.0)
        average_packet_size = float(getattr(flow, "average_packet_size", 0) or 0)
        if average_packet_size <= 0 and packet_count > 0:
            average_packet_size = float(byte_count) / float(packet_count)

        return SanitizedFlow(
            organization_id=organization_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(getattr(flow, "src_port", 0) or 0),
            dst_port=int(getattr(flow, "dst_port", 0) or 0),
            protocol=protocol,
            start_time=start_time,
            last_seen=last_seen,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            average_packet_size=average_packet_size,
            domain=self._normalize_host(getattr(flow, "domain", None)),
            sni=self._normalize_host(getattr(flow, "sni", None)),
            agent_id=str(getattr(flow, "agent_id", "") or ""),
            source_type=str(getattr(flow, "source_type", "agent") or "agent"),
            metadata_only=bool(getattr(flow, "metadata_only", False)),
            src_mac=src_mac,
            dst_mac=dst_mac,
            internal_device_ip=internal_ip,
            internal_device_mac=internal_mac,
            external_endpoint_ip=external_ip,
            network_scope=self._resolve_scope(src_scope, dst_scope),
        )


flow_sanitization_service = FlowSanitizationService()
