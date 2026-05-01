from __future__ import annotations

from functools import lru_cache
from dataclasses import dataclass
from typing import Optional

from .traffic_metadata import DomainHintCache, _extract_http_host, _extract_tls_sni, extract_flow_hints


HTTP_METHOD_PREFIXES = ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ")
HTTP_RESPONSE_PREFIX = "HTTP/"

TCP_SIGNATURE_PORTS = {
    22: ("SSH", "ssh"),
    25: ("SMTP", "smtp"),
    53: ("DNS-TCP", "dns"),
    80: ("HTTP", "http"),
    110: ("POP3", "pop3"),
    143: ("IMAP", "imap"),
    389: ("LDAP", "ldap"),
    443: ("HTTPS", "https"),
    445: ("SMB", "smb"),
    465: ("SMTPS", "smtps"),
    500: ("IKE", "ike"),
    587: ("SMTP", "smtp"),
    636: ("LDAPS", "ldaps"),
    993: ("IMAPS", "imaps"),
    995: ("POP3S", "pop3s"),
    1194: ("OpenVPN", "openvpn"),
    1433: ("MSSQL", "mssql"),
    1521: ("Oracle", "oracle"),
    1701: ("L2TP", "l2tp"),
    1883: ("MQTT", "mqtt"),
    3306: ("MySQL", "mysql"),
    3389: ("RDP", "rdp"),
    33848: ("RDP", "rdp"),
    3478: ("STUN", "stun"),
    3890: ("LDAP", "ldap"),
    4222: ("NATS", "nats"),
    4433: ("TLS", "tls"),
    4650: ("SMTP", "smtp"),
    5000: ("HTTP", "http"),
    5432: ("PostgreSQL", "postgresql"),
    5671: ("AMQPS", "amqps"),
    5672: ("AMQP", "amqp"),
    5900: ("VNC", "vnc"),
    5985: ("WinRM", "winrm"),
    5986: ("WinRM", "winrm"),
    6379: ("Redis", "redis"),
    7001: ("HTTP", "http"),
    8000: ("HTTP", "http"),
    8008: ("HTTP", "http"),
    8080: ("HTTP", "http"),
    8443: ("HTTPS", "https"),
    8883: ("MQTTS", "mqtts"),
    8888: ("HTTP", "http"),
    9200: ("Elasticsearch", "elasticsearch"),
    9300: ("Elasticsearch", "elasticsearch"),
    9443: ("HTTPS", "https"),
}

UDP_SIGNATURE_PORTS = {
    53: ("DNS", "dns"),
    67: ("DHCP", "dhcp"),
    68: ("DHCP", "dhcp"),
    123: ("NTP", "ntp"),
    137: ("NBNS", "nbns"),
    138: ("NBDS", "nbds"),
    389: ("CLDAP", "ldap"),
    500: ("IKE", "ike"),
    5060: ("SIP", "sip"),
    5061: ("SIPTLS", "siptls"),
    1194: ("OpenVPN", "openvpn"),
    1230: ("NTP", "ntp"),
    1434: ("MSSQL", "mssql"),
    1701: ("L2TP", "l2tp"),
    1900: ("SSDP", "ssdp"),
    3478: ("STUN", "stun"),
    4500: ("IPsec", "ipsec"),
    4789: ("VXLAN", "vxlan"),
    5001: ("HTTPS", "https"),
    5353: ("mDNS", "mdns"),
    5355: ("LLMNR", "llmnr"),
    5683: ("CoAP", "coap"),
    5684: ("CoAPS", "coaps"),
    443: ("QUIC", "quic"),
    8443: ("QUIC", "quic"),
}

IP_PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}

IPV6_NEXT_HEADER_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


@lru_cache(maxsize=1)
def _load_scapy_primitives():
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP  # type: ignore

    return ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP


@dataclass(frozen=True, slots=True)
class PacketAnalysis:
    transport_protocol: str
    application_protocol: str
    service_name: Optional[str]
    classification_source: str
    confidence: float
    signals: tuple[str, ...] = ()
    domain: Optional[str] = None
    sni: Optional[str] = None

    def as_dict(self) -> dict[str, object]:
        return {
            "transport_protocol": self.transport_protocol,
            "application_protocol": self.application_protocol,
            "service_name": self.service_name,
            "classification_source": self.classification_source,
            "confidence": self.confidence,
            "signals": list(self.signals),
            "domain": self.domain,
            "sni": self.sni,
        }


def _get_ip_layer(packet):
    _, _, _, _, IP, IPv6, _, _, _ = _load_scapy_primitives()
    if packet.haslayer(IP):
        return packet[IP]
    if packet.haslayer(IPv6):
        return packet[IPv6]
    return None


def _normalize_port(value: object) -> int:
    try:
        return max(int(value or 0), 0)
    except Exception:
        return 0


def _select_port(src_port: int, dst_port: int, mapping: dict[int, tuple[str, str]]) -> tuple[int | None, tuple[str, str] | None]:
    if dst_port in mapping:
        return dst_port, mapping[dst_port]
    if src_port in mapping:
        return src_port, mapping[src_port]
    return None, None


def _looks_like_http(payload: bytes) -> bool:
    if not payload:
        return False
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return False

    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
    return first_line.startswith(HTTP_METHOD_PREFIXES) or first_line.startswith(HTTP_RESPONSE_PREFIX)


def _looks_like_tls(payload: bytes) -> bool:
    return bool(payload and len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03)


def _transport_protocol(packet) -> str:
    ARP, _, _, ICMP, IP, IPv6, _, TCP, UDP = _load_scapy_primitives()
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"

    ip_layer = _get_ip_layer(packet)
    if ip_layer is None:
        return "UNKNOWN"

    if packet.haslayer(IP):
        return IP_PROTO_MAP.get(int(getattr(ip_layer, "proto", 0) or 0), f"IP-{int(getattr(ip_layer, 'proto', 0) or 0)}")

    if packet.haslayer(IPv6):
        return IPV6_NEXT_HEADER_MAP.get(int(getattr(ip_layer, "nh", 0) or 0), f"IPv6-{int(getattr(ip_layer, 'nh', 0) or 0)}")

    return "UNKNOWN"


def _classify_application(packet, transport_protocol: str, src_port: int, dst_port: int, domain: str | None, sni: str | None) -> PacketAnalysis:
    _, DNS, DNSQR, _, _, _, Raw, TCP, UDP = _load_scapy_primitives()
    payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    signals: list[str] = []
    application_protocol = transport_protocol
    service_name: Optional[str] = None
    source = "transport_fallback"
    confidence = 0.25 if transport_protocol not in {"UNKNOWN", "ARP"} else 0.1

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        application_protocol = "DNS"
        service_name = "dns"
        source = "dns"
        confidence = 1.0
        signals.append("dns_query")
        return PacketAnalysis(
            transport_protocol=transport_protocol,
            application_protocol=application_protocol,
            service_name=service_name,
            classification_source=source,
            confidence=confidence,
            signals=tuple(signals),
            domain=domain,
            sni=sni,
        )

    if transport_protocol == "TCP":
        port, signature = _select_port(src_port, dst_port, TCP_SIGNATURE_PORTS)
        if payload and _looks_like_http(payload):
            application_protocol = "HTTP"
            service_name = "http"
            source = "http_payload"
            confidence = 0.97
            signals.append("http_payload")
            host = _extract_http_host(payload)
            if host and not domain:
                domain = host
                signals.append("http_host")
        else:
            tls_domain = _extract_tls_sni(payload)
            if tls_domain and not sni:
                sni = tls_domain
                domain = domain or tls_domain
                signals.append("tls_sni")
            if tls_domain:
                if port in {443, 8443, 9443} or sni:
                    application_protocol = "HTTPS"
                    service_name = "https"
                    source = "tls"
                    confidence = 0.98 if sni else 0.92
                    signals.append("tls_handshake")
                else:
                    application_protocol = "TLS"
                    service_name = "tls"
                    source = "tls"
                    confidence = 0.9
                    signals.append("tls_handshake")
            elif payload and _looks_like_tls(payload):
                if port in {443, 8443, 9443} or sni:
                    application_protocol = "HTTPS"
                    service_name = "https"
                    source = "tls"
                    confidence = 0.98 if sni else 0.92
                    signals.append("tls_handshake")
                else:
                    application_protocol = "TLS"
                    service_name = "tls"
                    source = "tls"
                    confidence = 0.9
                    signals.append("tls_handshake")
            elif signature:
                application_protocol, service_name = signature
                source = "port_signature"
                confidence = 0.9
                signals.append(f"port_{port}")
            elif port in {443, 8443, 9443}:
                application_protocol = "HTTPS"
                service_name = "https"
                source = "port_signature"
                confidence = 0.8 if sni else 0.72
                signals.append(f"port_{port}")

        if application_protocol == transport_protocol and port is None:
            host = _extract_http_host(payload)
            if host:
                domain = domain or host
                application_protocol = "HTTP"
                service_name = "http"
                source = "http_payload"
                confidence = 0.9
                signals.append("http_host")

    elif transport_protocol == "UDP":
        port, signature = _select_port(src_port, dst_port, UDP_SIGNATURE_PORTS)
        if signature:
            application_protocol, service_name = signature
            source = "port_signature"
            confidence = 0.92
            signals.append(f"port_{port}")
            if application_protocol in {"DNS", "DHCP", "NTP", "NBNS", "NBDS", "LLMNR", "mDNS", "SSDP", "CLDAP"}:
                confidence = 1.0 if application_protocol == "DNS" else 0.95
        else:
            if port in {443, 8443} and payload:
                application_protocol = "QUIC"
                service_name = "quic"
                source = "port_signature"
                confidence = 0.82
                signals.append(f"port_{port}")
            elif port is not None:
                application_protocol = UDP_SIGNATURE_PORTS.get(port, ("UDP", None))[0]
                service_name = UDP_SIGNATURE_PORTS.get(port, ("UDP", None))[1]
                source = "port_signature"
                confidence = 0.75 if service_name else 0.25
                signals.append(f"port_{port}")

    elif transport_protocol in {"ICMP", "ICMPv6", "ARP"}:
        application_protocol = transport_protocol
        service_name = transport_protocol.lower()
        source = "transport"
        confidence = 1.0
        signals.append(transport_protocol.lower())

    if service_name is None and application_protocol in {"TCP", "UDP"}:
        service_name = None

    if domain and "domain_hint" not in signals and application_protocol in {"HTTP", "HTTPS", "TLS", "DNS"}:
        signals.append("domain_hint")

    return PacketAnalysis(
        transport_protocol=transport_protocol,
        application_protocol=application_protocol,
        service_name=service_name,
        classification_source=source,
        confidence=round(max(min(confidence, 1.0), 0.0), 3),
        signals=tuple(dict.fromkeys(signals)),
        domain=domain,
        sni=sni,
    )


def analyze_packet(packet, domain_cache: DomainHintCache | None = None) -> PacketAnalysis | None:
    _, _, _, _, IP, IPv6, _, TCP, UDP = _load_scapy_primitives()
    ip_layer = _get_ip_layer(packet)
    if ip_layer is None:
        return None

    transport_protocol = _transport_protocol(packet)
    src_port = _normalize_port(getattr(packet[TCP], "sport", 0) if packet.haslayer(TCP) else getattr(packet[UDP], "sport", 0) if packet.haslayer(UDP) else 0)
    dst_port = _normalize_port(getattr(packet[TCP], "dport", 0) if packet.haslayer(TCP) else getattr(packet[UDP], "dport", 0) if packet.haslayer(UDP) else 0)

    hints = extract_flow_hints(packet, domain_cache)
    domain = hints.get("domain")
    sni = hints.get("sni")

    analysis = _classify_application(packet, transport_protocol, src_port, dst_port, domain, sni)
    if not analysis.domain and domain:
        analysis = PacketAnalysis(
            transport_protocol=analysis.transport_protocol,
            application_protocol=analysis.application_protocol,
            service_name=analysis.service_name,
            classification_source=analysis.classification_source,
            confidence=analysis.confidence,
            signals=analysis.signals,
            domain=domain,
            sni=analysis.sni,
        )
    if not analysis.sni and sni:
        analysis = PacketAnalysis(
            transport_protocol=analysis.transport_protocol,
            application_protocol=analysis.application_protocol,
            service_name=analysis.service_name,
            classification_source=analysis.classification_source,
            confidence=analysis.confidence,
            signals=analysis.signals,
            domain=analysis.domain,
            sni=sni,
        )
    return analysis
