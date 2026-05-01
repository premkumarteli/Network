from __future__ import annotations

import time
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from .analysis import analyze_packet
from .traffic_metadata import DomainHintCache


@lru_cache(maxsize=1)
def _load_scapy_primitives():
    from scapy.all import Ether, IP, IPv6, TCP, UDP  # type: ignore

    return Ether, IP, IPv6, TCP, UDP


@dataclass(frozen=True, slots=True)
class FlowObservation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    last_seen: str
    packet_count: int
    byte_count: int
    duration: float
    average_packet_size: float
    agent_id: str
    organization_id: str
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    source_type: str = "agent"
    metadata_only: bool = False
    application_protocol: Optional[str] = None
    service_name: Optional[str] = None
    analysis_source: str = "transport_fallback"
    analysis_confidence: float = 0.0
    analysis_signals: tuple[str, ...] = ()

    @classmethod
    def from_packet_observation(
        cls,
        observation: "PacketObservation",
        *,
        agent_id: str,
        organization_id: str,
    ) -> "FlowObservation":
        observed_at = datetime.fromtimestamp(observation.observed_at, tz=timezone.utc)
        iso_timestamp = observed_at.isoformat()
        return cls(
            src_ip=observation.src_ip,
            dst_ip=observation.dst_ip,
            src_port=observation.src_port,
            dst_port=observation.dst_port,
            protocol=observation.protocol,
            start_time=iso_timestamp,
            last_seen=iso_timestamp,
            packet_count=1,
            byte_count=observation.packet_size,
            duration=0.0,
            average_packet_size=float(observation.packet_size),
            agent_id=agent_id,
            organization_id=organization_id,
            domain=observation.domain,
            sni=observation.sni,
            src_mac=observation.src_mac,
            dst_mac=observation.dst_mac,
            source_type=observation.source_type,
            metadata_only=observation.metadata_only,
            application_protocol=observation.application_protocol,
            service_name=observation.service_name,
            analysis_source=observation.analysis_source,
            analysis_confidence=observation.analysis_confidence,
            analysis_signals=observation.analysis_signals,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": self.duration,
            "average_packet_size": self.average_packet_size,
            "agent_id": self.agent_id,
            "organization_id": self.organization_id,
            "domain": self.domain,
            "sni": self.sni,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "source_type": self.source_type,
            "metadata_only": self.metadata_only,
            "application_protocol": self.application_protocol,
            "service_name": self.service_name,
            "analysis_source": self.analysis_source,
            "analysis_confidence": self.analysis_confidence,
            "analysis_signals": list(self.analysis_signals),
        }


FlowSummary = FlowObservation


@dataclass(frozen=True, slots=True)
class PacketObservation:
    observed_at: float
    source_type: str
    metadata_only: bool
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    application_protocol: Optional[str] = None
    service_name: Optional[str] = None
    analysis_source: str = "transport_fallback"
    analysis_confidence: float = 0.0
    analysis_signals: tuple[str, ...] = ()

    @property
    def flow_key(self) -> tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def observed_at_iso(self) -> str:
        return datetime.fromtimestamp(self.observed_at, tz=timezone.utc).isoformat()

    def to_flow_observation(self, *, agent_id: str, organization_id: str) -> FlowObservation:
        return FlowObservation.from_packet_observation(
            self,
            agent_id=agent_id,
            organization_id=organization_id,
        )

    @classmethod
    def from_packet(
        cls,
        packet,
        *,
        source_type: str = "agent",
        metadata_only: bool = False,
        domain_cache: DomainHintCache | None = None,
        observed_at: float | None = None,
    ) -> "PacketObservation | None":
        Ether, IP, IPv6, TCP, UDP = _load_scapy_primitives()
        if not packet or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return None

        analysis = analyze_packet(packet, domain_cache=domain_cache)
        ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        if packet.haslayer(TCP):
            proto = "TCP"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        else:
            proto = analysis.transport_protocol if analysis else str(getattr(ip, "proto", getattr(ip, "nh", "UNKNOWN")))
            sport = 0
            dport = 0

        domain = getattr(packet, "captured_domain", None)
        sni = getattr(packet, "captured_sni", None)
        if analysis:
            domain = domain or analysis.domain
            sni = sni or analysis.sni

        return cls(
            observed_at=observed_at if observed_at is not None else time.time(),
            source_type=str(source_type or "agent"),
            metadata_only=bool(metadata_only),
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            src_port=sport,
            dst_port=dport,
            protocol=proto,
            packet_size=len(packet),
            domain=domain,
            sni=sni,
            src_mac=packet[Ether].src if packet.haslayer(Ether) else None,
            dst_mac=packet[Ether].dst if packet.haslayer(Ether) else None,
            application_protocol=analysis.application_protocol if analysis else proto,
            service_name=analysis.service_name if analysis else None,
            analysis_source=analysis.classification_source if analysis else "transport_fallback",
            analysis_confidence=analysis.confidence if analysis else 0.0,
            analysis_signals=analysis.signals if analysis else (),
        )


@dataclass(frozen=True, slots=True)
class DpiObservation:
    browser_name: str
    process_name: str
    page_url: str
    base_domain: str
    page_title: str
    content_category: str
    content_id: Optional[str]
    search_query: Optional[str]
    http_method: str
    status_code: Optional[int]
    content_type: Optional[str]
    request_bytes: int
    response_bytes: int
    snippet_redacted: Optional[str]
    timestamp: str
    app: str
    source_type: str = "agent"
    metadata_only: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {
            "browser_name": self.browser_name,
            "process_name": self.process_name,
            "page_url": self.page_url,
            "base_domain": self.base_domain,
            "page_title": self.page_title,
            "content_category": self.content_category,
            "content_id": self.content_id,
            "search_query": self.search_query,
            "http_method": self.http_method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "snippet_redacted": self.snippet_redacted,
            "timestamp": self.timestamp,
            "app": self.app,
            "source_type": self.source_type,
            "metadata_only": self.metadata_only,
        }
