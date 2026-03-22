from __future__ import annotations

import ipaddress
from typing import Optional


RFC1918_DEVICE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def normalize_ip(value: object) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def is_rfc1918_device_ip(value: object) -> bool:
    ip_value = normalize_ip(value)
    if not ip_value:
        return False

    parsed = ipaddress.ip_address(ip_value)
    if parsed.version != 4:
        return False

    return any(parsed in network for network in RFC1918_DEVICE_NETWORKS)


def is_multicast_or_broadcast_ip(value: object) -> bool:
    ip_value = normalize_ip(value)
    if not ip_value:
        return False

    parsed = ipaddress.ip_address(ip_value)
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        return True

    if isinstance(parsed, ipaddress.IPv4Address):
        octets = ip_value.split(".")
        if octets[-1] == "255":
            return True
    return False


def classify_ip_scope(value: object) -> str:
    ip_value = normalize_ip(value)
    if not ip_value:
        return "invalid"
    if is_multicast_or_broadcast_ip(ip_value):
        return "control"
    if is_rfc1918_device_ip(ip_value):
        return "internal"
    return "external"


def normalize_mac(value: object) -> Optional[str]:
    if value is None:
        return None

    raw = str(value).strip().lower()
    if not raw or raw in {"-", "unknown", "none", "null"}:
        return None

    candidate = raw.replace("-", ":").replace(".", "")
    if "." in raw and len(candidate) == 12:
        candidate = ":".join(candidate[index:index + 2] for index in range(0, 12, 2))

    parts = candidate.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return None

    try:
        normalized = ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return None

    if normalized == "ff:ff:ff:ff:ff:ff":
        return None
    return normalized


def is_unicast_mac(value: object) -> bool:
    normalized = normalize_mac(value)
    if not normalized:
        return False

    first_octet = int(normalized.split(":")[0], 16)
    return (first_octet & 1) == 0
