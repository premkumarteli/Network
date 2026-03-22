from app.services.application_service import application_service


def test_meaningful_session_filters_internal_unknown_noise():
    row = {
        "device_ip": "10.0.0.5",
        "external_ip": None,
        "application": "Unknown",
        "domain": None,
        "protocol": "TCP",
    }

    assert application_service._is_meaningful_session(row) is False


def test_meaningful_session_filters_udp_dns_like_noise_without_external_ip():
    row = {
        "device_ip": "10.0.0.5",
        "external_ip": None,
        "application": "ChatGPT",
        "domain": "chatgpt.com",
        "protocol": "UDP",
    }

    assert application_service._is_meaningful_session(row) is False


def test_meaningful_session_keeps_external_application_session():
    row = {
        "device_ip": "10.0.0.5",
        "external_ip": "104.18.37.228",
        "application": "ChatGPT",
        "domain": "chat.openai.com",
        "protocol": "TCP",
    }

    assert application_service._is_meaningful_session(row) is True
