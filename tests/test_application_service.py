from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.application_service import application_service


def test_get_base_domain_uses_effective_tld_plus_one():
    assert application_service.get_base_domain("mail.google.com") == "google.com"
    assert application_service.get_base_domain("api.whatsapp.net") == "whatsapp.net"


def test_classify_app_prefers_sni_over_domain():
    row = SimpleNamespace(
        sni="chat.openai.com",
        domain="www.youtube.com",
        dst_ip="104.18.33.45",
    )
    assert application_service.classify_app(row) == "ChatGPT"


def test_classify_app_maps_known_domains_by_base_domain():
    assert application_service.classify_app(SimpleNamespace(domain="rr1---sn.googlevideo.com")) == "YouTube"
    assert application_service.classify_app(SimpleNamespace(domain="www.instagram.com")) == "Instagram"
    assert application_service.classify_app(SimpleNamespace(domain="static.whatsapp.net")) == "WhatsApp"
    assert application_service.classify_app(SimpleNamespace(domain="chat.openai.com")) == "ChatGPT"
    assert application_service.classify_app(SimpleNamespace(domain="www.perplexity.ai")) == "Perplexity"
    assert application_service.classify_by_domain("cloudapp.azure.com") == "Azure CloudApp"
    assert application_service.classify_by_domain("main.vscode-cdn.net") == "Visual Studio Code"
    assert application_service.classify_by_domain("f-log-extension.grammarly.io") == "Grammarly"
    assert application_service.classify_by_domain("crl3.digicert.com") == "DigiCert CRL"


def test_classify_app_uses_asn_when_domain_is_known_but_uncategorized(monkeypatch):
    monkeypatch.setattr(application_service, "classify_by_asn", lambda _: "AWS")
    row = SimpleNamespace(domain="downloads.example.org", dst_ip="54.240.1.1")
    assert application_service.classify_app(row) == "AWS"


def test_classify_app_uses_asn_for_shared_infrastructure_domain(monkeypatch):
    monkeypatch.setattr(application_service, "classify_by_asn", lambda _: "Google")
    row = SimpleNamespace(domain="edge.cloudflare.com", dst_ip="8.8.8.8")
    assert application_service.classify_app(row) == "Google"


def test_classify_app_uses_external_endpoint_ip_for_asn_fallback(monkeypatch):
    monkeypatch.setattr(application_service, "classify_by_asn", lambda ip: "Google" if ip == "8.8.8.8" else None)
    row = SimpleNamespace(domain="unknown.example.org", dst_ip="203.0.113.5", external_endpoint_ip="8.8.8.8")
    assert application_service.classify_app(row) == "Google"


def test_classify_app_uses_transport_labels_for_hostless_sessions():
    assert (
        application_service.classify_app(
            SimpleNamespace(domain=None, sni=None, dst_ip="8.8.8.8", src_port=52100, dst_port=53, protocol="UDP")
        )
        == "DNS"
    )
    assert (
        application_service.classify_app(
            SimpleNamespace(domain=None, sni=None, dst_ip="1.1.1.1", src_port=52100, dst_port=443, protocol="TCP")
        )
        == "HTTPS"
    )


def test_resolve_application_label_promotes_generic_transport_labels():
    assert (
        application_service.resolve_application_label(
            SimpleNamespace(
                application="HTTPS",
                domain="chat.openai.com",
                sni="chat.openai.com",
                dst_ip="104.18.33.45",
            )
        )
        == "ChatGPT"
    )
    assert (
        application_service.resolve_application_label(
            SimpleNamespace(
                application="DNS",
                domain="beacons.gcp.gvt2.com",
                sni=None,
                dst_ip="8.8.8.8",
            )
        )
        == "Google Services"
    )


def test_build_sessions_uses_transport_hints_for_hostless_traffic(monkeypatch):
    rows = [
        {
            "device_ip": "10.0.0.10",
            "external_ip": "8.8.8.8",
            "application": "Other",
            "domain": None,
            "protocol": "UDP",
            "src_port": 52100,
            "dst_port": 53,
            "total_packets": 3,
            "total_bytes": 300,
            "first_seen": datetime(2026, 4, 26, 1, 0, 0, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 4, 26, 1, 0, 2, tzinfo=timezone.utc),
        },
        {
            "device_ip": "10.0.0.10",
            "external_ip": "1.1.1.1",
            "application": "Unknown",
            "domain": None,
            "protocol": "TCP",
            "src_port": 52101,
            "dst_port": 443,
            "total_packets": 4,
            "total_bytes": 400,
            "first_seen": datetime(2026, 4, 26, 1, 1, 0, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 4, 26, 1, 1, 4, tzinfo=timezone.utc),
        },
    ]
    monkeypatch.setattr(application_service, "_fetch_recent_sessions", lambda *args, **kwargs: rows)

    sessions = application_service._build_sessions(None, None, 60)

    assert [session["application"] for session in sessions] == ["DNS", "HTTPS"]
    assert [session["src_port"] for session in sessions] == [52100, 52101]
    assert [session["dst_port"] for session in sessions] == [53, 443]


def test_get_application_devices_aggregates_sessions_by_device(monkeypatch):
    now = datetime.now(timezone.utc)
    sessions = [
        {
            "device_ip": "10.0.0.10",
            "application": "ChatGPT",
            "bandwidth_bytes": 100,
            "first_seen": now - timedelta(minutes=20),
            "last_seen": now - timedelta(minutes=18),
        },
        {
            "device_ip": "10.0.0.10",
            "application": "ChatGPT",
            "bandwidth_bytes": 250,
            "first_seen": now - timedelta(minutes=15),
            "last_seen": now - timedelta(minutes=8),
        },
        {
            "device_ip": "10.0.0.10",
            "application": "ChatGPT",
            "bandwidth_bytes": 400,
            "first_seen": now - timedelta(minutes=6),
            "last_seen": now - timedelta(minutes=1),
        },
    ]

    monkeypatch.setattr(application_service, "ensure_schema", lambda *_: None)
    monkeypatch.setattr(
        "app.services.application_service.device_service.get_devices",
        lambda *args, **kwargs: [{"ip": "10.0.0.10", "hostname": "DESKTOP-IFIA9GL", "management_mode": "managed"}],
    )
    monkeypatch.setattr(application_service, "_build_sessions", lambda *args, **kwargs: sessions)

    rows = application_service.get_application_devices(None, "ChatGPT")

    assert len(rows) == 1
    row = rows[0]
    assert row["device_ip"] == "10.0.0.10"
    assert row["hostname"] == "DESKTOP-IFIA9GL"
    assert row["status"] == "Active"
    assert row["bandwidth_bytes"] == 750
    assert row["session_count"] == 3
    assert row["active_session_count"] == 1
    assert row["runtime_seconds"] == 19 * 60


def test_classify_app_separates_other_from_unknown(monkeypatch):
    monkeypatch.setattr(application_service, "classify_by_asn", lambda _: None)
    assert application_service.classify_app(SimpleNamespace(domain="unknown.example.org", dst_ip="1.1.1.1")) == "Other"
    assert application_service.classify_app(SimpleNamespace(domain=None, sni=None, dst_ip="1.1.1.1")) == "Unknown"


def test_select_device_ip_prefers_private_endpoint_over_remote_ip():
    row = {"src_ip": "10.128.88.96", "dst_ip": "51.116.253.169"}
    assert application_service._select_device_ip(row) == "10.128.88.96"


def test_noise_flow_filters_dns_and_reverse_lookup():
    dns_row = {"src_port": 52100, "dst_port": 53, "domain": "chatgpt.com"}
    arpa_row = {"src_port": 60000, "dst_port": 60001, "domain": "172.88.128.10.in-addr.arpa"}
    assert application_service._is_noise_flow(dns_row) is True
    assert application_service._is_noise_flow(arpa_row) is True


def test_runtime_formatting_is_human_readable():
    assert application_service._format_runtime(45) == "45s"
    assert application_service._format_runtime(125) == "2m 5s"
    assert application_service._format_runtime(3720) == "1h 2m"
