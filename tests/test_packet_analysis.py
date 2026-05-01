from scapy.all import DNS, DNSQR, Ether, IP, IPv6, Raw, TCP, UDP  # type: ignore

from shared.collector import PacketObservation, analyze_packet


def test_analyze_packet_classifies_dns():
    packet = IP(src="10.0.0.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))

    analysis = analyze_packet(packet)

    assert analysis is not None
    assert analysis.transport_protocol == "UDP"
    assert analysis.application_protocol == "DNS"
    assert analysis.service_name == "dns"
    assert analysis.classification_source == "dns"
    assert analysis.confidence == 1.0


def test_analyze_packet_classifies_http_host_header():
    packet = (
        Ether()
        / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / TCP(sport=54001, dport=80)
        / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netvisor\r\n\r\n")
    )

    analysis = analyze_packet(packet)

    assert analysis is not None
    assert analysis.transport_protocol == "TCP"
    assert analysis.application_protocol == "HTTP"
    assert analysis.service_name == "http"
    assert analysis.domain == "example.com"
    assert analysis.classification_source == "http_payload"
    assert analysis.confidence >= 0.9


def test_analyze_packet_classifies_tls_sni(monkeypatch):
    monkeypatch.setattr("shared.collector.analysis._extract_tls_sni", lambda _: "github.com")
    packet = IP(src="10.0.0.10", dst="140.82.112.4") / TCP(sport=54001, dport=443) / Raw(load=b"client-hello")

    analysis = analyze_packet(packet)

    assert analysis is not None
    assert analysis.transport_protocol == "TCP"
    assert analysis.application_protocol == "HTTPS"
    assert analysis.service_name == "https"
    assert analysis.domain == "github.com"
    assert analysis.sni == "github.com"
    assert analysis.classification_source == "tls"
    assert analysis.confidence >= 0.95


def test_packet_observation_supports_ipv6_and_analysis():
    packet = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=12345, dport=443)
    )

    observation = PacketObservation.from_packet(packet, source_type="gateway", metadata_only=True)

    assert observation is not None
    assert observation.src_ip == "2001:db8::1"
    assert observation.dst_ip == "2001:db8::2"
    assert observation.protocol == "TCP"
    assert observation.application_protocol == "HTTPS"
    assert observation.service_name == "https"
