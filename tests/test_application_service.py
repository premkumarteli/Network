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


def test_classify_app_uses_asn_when_domain_is_known_but_uncategorized(monkeypatch):
    monkeypatch.setattr(application_service, "classify_by_asn", lambda _: "AWS")
    row = SimpleNamespace(domain="downloads.example.org", dst_ip="54.240.1.1")
    assert application_service.classify_app(row) == "AWS"


def test_classify_app_uses_asn_for_shared_infrastructure_domain(monkeypatch):
    monkeypatch.setattr(application_service, "classify_by_asn", lambda _: "Google")
    row = SimpleNamespace(domain="edge.cloudflare.com", dst_ip="8.8.8.8")
    assert application_service.classify_app(row) == "Google"


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
