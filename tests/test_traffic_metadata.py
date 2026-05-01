from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP, UDP  # type: ignore

from agent.traffic_metadata import DomainHintCache, extract_domain_hint, extract_flow_hints


def test_dns_response_populates_domain_cache_for_followup_flow():
    cache = DomainHintCache()
    dns_response = (
        IP(src="10.128.88.96", dst="10.128.88.172")
        / UDP(sport=53, dport=54000)
        / DNS(
            id=1,
            qr=1,
            qd=DNSQR(qname="chatgpt.com"),
            an=DNSRR(rrname="chatgpt.com", type="A", rdata="51.116.253.169"),
            ancount=1,
        )
    )

    assert extract_domain_hint(dns_response, cache) == "chatgpt.com"

    followup = IP(src="10.128.88.172", dst="51.116.253.169") / UDP(sport=54001, dport=443)
    assert extract_domain_hint(followup, cache) == "chatgpt.com"


def test_extract_flow_hints_prefers_tls_sni_when_available(monkeypatch):
    cache = DomainHintCache()
    monkeypatch.setattr("agent.traffic_metadata._extract_tls_sni", lambda _: "github.com")

    packet = (
        IP(src="10.128.88.172", dst="140.82.112.4")
        / TCP(sport=54001, dport=443)
        / Raw(load=b"client-hello")
    )

    hints = extract_flow_hints(packet, cache)

    assert hints == {"domain": "github.com", "sni": "github.com"}
    assert extract_domain_hint(packet, cache) == "github.com"


def test_extract_flow_hints_uses_http_host_header():
    cache = DomainHintCache()
    packet = (
        IP(src="10.128.88.172", dst="93.184.216.34")
        / TCP(sport=54001, dport=80)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netvisor\r\n\r\n")
    )

    hints = extract_flow_hints(packet, cache)

    assert hints == {"domain": "example.com", "sni": None}
    assert extract_domain_hint(packet, cache) == "example.com"

