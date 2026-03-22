from __future__ import annotations

import ipaddress
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP  # type: ignore


def _normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None

    value = domain.strip().lower().rstrip(".")
    if not value or " " in value:
        return None
    return value


def _is_ip_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_trackable_private_ip(value: str | None) -> bool:
    if not _is_ip_address(value):
        return False

    ip = ipaddress.ip_address(value)
    return (
        ip.version == 4
        and ip.is_private
        and not ip.is_loopback
        and not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_reserved
        and not ip.is_link_local
    )


def _select_remote_ip(packet) -> str | None:
    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_private = _is_trackable_private_ip(src_ip)
    dst_private = _is_trackable_private_ip(dst_ip)

    if src_private and not dst_private:
        return dst_ip
    if dst_private and not src_private:
        return src_ip
    return None


class DomainHintCache:
    def __init__(self, ttl_seconds: int = 300, max_entries: int = 2048) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: dict[str, tuple[str, float]] = {}

    def _prune(self) -> None:
        if not self._entries:
            return

        now = time.time()
        expired = [ip for ip, (_, expires_at) in self._entries.items() if expires_at <= now]
        for ip in expired:
            self._entries.pop(ip, None)

        if len(self._entries) <= self.max_entries:
            return

        oldest = sorted(self._entries.items(), key=lambda item: item[1][1])[: len(self._entries) - self.max_entries]
        for ip, _ in oldest:
            self._entries.pop(ip, None)

    def remember(self, ip_value: str | None, domain: str | None) -> None:
        normalized_domain = _normalize_domain(domain)
        if not normalized_domain or not _is_ip_address(ip_value):
            return

        self._prune()
        self._entries[str(ip_value)] = (normalized_domain, time.time() + self.ttl_seconds)

    def lookup(self, ip_value: str | None) -> str | None:
        if not _is_ip_address(ip_value):
            return None

        self._prune()
        record = self._entries.get(str(ip_value))
        if not record:
            return None
        return record[0]

    def observe_dns(self, packet) -> str | None:
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        question_name = _normalize_domain(packet[DNSQR].qname.decode(errors="ignore"))
        dns_layer = packet[DNS]

        if dns_layer.qr != 1:
            return question_name

        answer = dns_layer.an
        answer_count = int(getattr(dns_layer, "ancount", 0) or 0)
        for _ in range(answer_count):
            if not isinstance(answer, DNSRR):
                break
            answer_domain = _normalize_domain(
                answer.rrname.decode(errors="ignore") if hasattr(answer.rrname, "decode") else str(answer.rrname)
            ) or question_name
            if answer.type in (1, 28):
                self.remember(str(answer.rdata), answer_domain)
            answer = answer.payload

        return question_name


def _extract_tls_sni(payload: bytes) -> str | None:
    if len(payload) < 5 or payload[0] != 0x16:
        return None

    record_length = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_length:
        return None

    handshake = payload[5 : 5 + record_length]
    if len(handshake) < 4 or handshake[0] != 0x01:
        return None

    body = handshake[4:]
    if len(body) < 34:
        return None

    index = 34
    if index >= len(body):
        return None

    session_id_length = body[index]
    index += 1 + session_id_length
    if index + 2 > len(body):
        return None

    cipher_suites_length = int.from_bytes(body[index : index + 2], "big")
    index += 2 + cipher_suites_length
    if index >= len(body):
        return None

    compression_length = body[index]
    index += 1 + compression_length
    if index + 2 > len(body):
        return None

    extensions_length = int.from_bytes(body[index : index + 2], "big")
    index += 2
    extensions_end = min(len(body), index + extensions_length)

    while index + 4 <= extensions_end:
        extension_type = int.from_bytes(body[index : index + 2], "big")
        extension_size = int.from_bytes(body[index + 2 : index + 4], "big")
        extension_start = index + 4
        extension_end = extension_start + extension_size
        if extension_end > extensions_end:
            return None

        if extension_type == 0x0000 and extension_size >= 5:
            server_name_list_length = int.from_bytes(body[extension_start : extension_start + 2], "big")
            pointer = extension_start + 2
            list_end = min(extension_end, pointer + server_name_list_length)
            while pointer + 3 <= list_end:
                name_type = body[pointer]
                name_length = int.from_bytes(body[pointer + 1 : pointer + 3], "big")
                pointer += 3
                if pointer + name_length > list_end:
                    return None
                if name_type == 0:
                    return _normalize_domain(body[pointer : pointer + name_length].decode("utf-8", errors="ignore"))
                pointer += name_length

        index = extension_end

    return None


def extract_flow_hints(packet, domain_cache: DomainHintCache | None = None) -> dict[str, str | None]:
    """
    Extract DNS/SNI/domain hints for a packet.
    Returns:
    - domain: DNS/cached hostname hint for the remote endpoint
    - sni: TLS Server Name Indication when present
    """
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = (
            domain_cache.observe_dns(packet)
            if domain_cache
            else _normalize_domain(packet[DNSQR].qname.decode(errors="ignore"))
        )
        return {"domain": domain, "sni": None}

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tls_domain = _extract_tls_sni(bytes(packet[Raw].load))
        if tls_domain and domain_cache:
            domain_cache.remember(_select_remote_ip(packet), tls_domain)
        if tls_domain:
            return {"domain": tls_domain, "sni": tls_domain}

    if domain_cache:
        cached_domain = domain_cache.lookup(_select_remote_ip(packet))
        return {"domain": cached_domain, "sni": None}

    return {"domain": None, "sni": None}


def extract_domain_hint(packet, domain_cache: DomainHintCache | None = None) -> str | None:
    hints = extract_flow_hints(packet, domain_cache)
    return hints.get("sni") or hints.get("domain")
