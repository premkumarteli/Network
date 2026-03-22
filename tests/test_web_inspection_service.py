from app.services.web_inspection_service import web_inspection_service


def test_default_policy_uses_expected_defaults():
    policy = web_inspection_service._default_policy("AGENT-1", "10.0.0.5")

    assert policy["inspection_enabled"] is False
    assert "chrome.exe" in policy["allowed_processes"]
    assert "youtube.com" in policy["allowed_domains"]
    assert policy["snippet_max_bytes"] == 256


def test_coerce_event_normalizes_web_event_payload():
    event = web_inspection_service._coerce_event(
        {
            "organization_id": "default-org-id",
            "agent_id": "AGENT-1",
            "device_ip": "10.0.0.5",
            "process_name": "chrome.exe",
            "browser_name": "Chrome",
            "page_url": "https://www.youtube.com/watch?v=abc123",
            "base_domain": "youtube.com",
            "page_title": "Video",
            "content_category": "video",
            "content_id": "abc123",
            "http_method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "request_bytes": 100,
            "response_bytes": 200,
            "snippet_redacted": "hello",
            "snippet_hash": "hash",
            "first_seen": "2026-03-22 12:00:00",
            "last_seen": "2026-03-22 12:00:01",
        }
    )

    assert event is not None
    assert event[1] == "AGENT-1"
    assert event[2] == "10.0.0.5"
    assert event[5] == "https://www.youtube.com/watch?v=abc123"
    assert event[6] == "youtube.com"
