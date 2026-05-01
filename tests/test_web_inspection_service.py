from datetime import datetime, timezone

from app.services.web_inspection_service import web_inspection_service


def test_default_policy_uses_expected_defaults():
    policy = web_inspection_service._default_policy("AGENT-1", "10.0.0.5")

    assert policy["inspection_enabled"] is False
    assert "chrome.exe" in policy["allowed_processes"]
    assert "youtube.com" in policy["allowed_domains"]
    assert policy["snippet_max_bytes"] == 256
    assert policy["privacy_guard_enabled"] is True
    assert policy["sensitive_destination_bypass_enabled"] is True


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


def test_coerce_event_bypasses_sensitive_destinations():
    event = web_inspection_service._coerce_event(
        {
            "organization_id": "default-org-id",
            "agent_id": "AGENT-1",
            "device_ip": "10.0.0.5",
            "process_name": "chrome.exe",
            "browser_name": "Chrome",
            "page_url": "https://www.paypal.com/signin",
            "base_domain": "paypal.com",
            "page_title": "PayPal",
            "content_category": "web",
            "http_method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "request_bytes": 100,
            "response_bytes": 200,
            "snippet_redacted": "secret",
            "snippet_hash": "hash",
            "first_seen": "2026-03-22 12:00:00",
            "last_seen": "2026-03-22 12:00:01",
        }
    )

    assert event is None


class _StoreCursor:
    def __init__(self):
        self.executed = []
        self.rows = []
        self.pending = None
        self.insert_count = 0
        self.update_count = 0

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT id, event_count FROM web_events"):
            device_ip, base_domain, page_url, content_id, page_title = params
            lookup_key = (device_ip, base_domain, page_url, content_id or page_title)
            self.pending = None
            for row in reversed(self.rows):
                row_key = (
                    row["device_ip"],
                    row["base_domain"],
                    row["page_url"],
                    row["content_id"] or row["page_title"],
                )
                if row_key == lookup_key:
                    self.pending = {"id": row["id"], "event_count": row["event_count"]}
                    break
        elif normalized.startswith("INSERT INTO web_events"):
            self.insert_count += 1
            row = dict(params)
            row["id"] = len(self.rows) + 1
            row["event_count"] = 1
            self.rows.append(row)
        elif normalized.startswith("UPDATE web_events"):
            self.update_count += 1
            update_params = params
            event_id = update_params[-1]
            for row in self.rows:
                if row["id"] == event_id:
                    row["event_count"] += 1
                    break

    def fetchone(self):
        return self.pending

    def close(self):
        return None


class _StoreConnection:
    def __init__(self):
        self.cursor_obj = _StoreCursor()
        self.committed = False

    def cursor(self, dictionary=False):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        return None

    def close(self):
        return None


class _ActivityCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def execute(self, query, params=None):
        self.executed.append((" ".join(query.split()), params))

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return None

    def close(self):
        return None


class _ActivityConnection:
    def __init__(self, rows):
        self.cursor_obj = _ActivityCursor(rows)

    def cursor(self, dictionary=False):
        return self.cursor_obj

    def commit(self):
        return None

    def rollback(self):
        return None

    def close(self):
        return None


def test_store_events_uses_page_url_to_keep_tabs_distinct(monkeypatch):
    conn = _StoreConnection()
    monkeypatch.setattr(web_inspection_service, "ensure_schema", lambda db_conn: None)
    monkeypatch.setattr(
        "app.services.web_inspection_service.threat_intel.check_threat",
        lambda event: {"risk_level": "safe", "threat_msg": None},
    )

    base_event = {
        "organization_id": "default-org-id",
        "agent_id": "AGENT-1",
        "device_ip": "10.0.0.5",
        "process_name": "chrome.exe",
        "browser_name": "Chrome",
        "base_domain": "example.com",
        "page_title": "Example",
        "content_category": "web",
        "content_id": None,
        "http_method": "GET",
        "status_code": 200,
        "content_type": "text/html",
        "request_bytes": 100,
        "response_bytes": 200,
        "snippet_redacted": "redacted",
        "snippet_hash": "hash",
        "first_seen": "2026-03-22 12:00:00",
        "last_seen": "2026-03-22 12:00:01",
    }

    stored = web_inspection_service.store_events(
        conn,
        [
            {**base_event, "page_url": "https://example.com/tab-1"},
            {**base_event, "page_url": "https://example.com/tab-2"},
        ],
    )

    assert stored == 2
    assert conn.cursor_obj.insert_count == 2
    assert any("page_url = %s" in query for query, _ in conn.cursor_obj.executed if query.startswith("SELECT id, event_count"))


def test_grouped_evidence_rolls_up_tabs_and_normalizes_risk(monkeypatch):
    rows = [
        {
            "id": 1,
            "agent_id": "AGENT-1",
            "device_ip": "10.0.0.5",
            "process_name": "chrome.exe",
            "browser_name": "Google Chrome",
            "page_url": "https://example.com/tab-1",
            "base_domain": "example.com",
            "page_title": "Example",
            "content_category": "web",
            "content_id": None,
            "search_query": "alpha",
            "http_method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "request_bytes": 100,
            "response_bytes": 200,
            "snippet_redacted": "first",
            "snippet_hash": "hash-1",
            "confidence_score": 0.4,
            "event_count": 1,
            "risk_level": "yellow",
            "threat_msg": "Suspicious Keyword Detected",
            "first_seen": datetime(2026, 4, 26, 1, 0, 0, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 4, 26, 1, 0, 5, tzinfo=timezone.utc),
        },
        {
            "id": 2,
            "agent_id": "AGENT-1",
            "device_ip": "10.0.0.5",
            "process_name": "chrome.exe",
            "browser_name": "Google Chrome",
            "page_url": "https://example.com/tab-1",
            "base_domain": "example.com",
            "page_title": "Example",
            "content_category": "web",
            "content_id": None,
            "search_query": "alpha",
            "http_method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "request_bytes": 50,
            "response_bytes": 25,
            "snippet_redacted": "second",
            "snippet_hash": "hash-2",
            "confidence_score": 0.9,
            "event_count": 2,
            "risk_level": "red",
            "threat_msg": "Executable Download Detected",
            "first_seen": datetime(2026, 4, 26, 1, 0, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 4, 26, 1, 0, 7, tzinfo=timezone.utc),
        },
        {
            "id": 3,
            "agent_id": "AGENT-1",
            "device_ip": "10.0.0.5",
            "process_name": "chrome.exe",
            "browser_name": "Google Chrome",
            "page_url": "https://example.com/tab-2",
            "base_domain": "example.com",
            "page_title": "Example Two",
            "content_category": "web",
            "content_id": None,
            "search_query": None,
            "http_method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "request_bytes": 12,
            "response_bytes": 18,
            "snippet_redacted": "third",
            "snippet_hash": "hash-3",
            "confidence_score": 0.3,
            "event_count": 1,
            "risk_level": "safe",
            "threat_msg": None,
            "first_seen": datetime(2026, 4, 26, 1, 2, 0, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 4, 26, 1, 2, 3, tzinfo=timezone.utc),
        },
    ]
    conn = _ActivityConnection(rows)
    monkeypatch.setattr(web_inspection_service, "ensure_schema", lambda db_conn: None)
    monkeypatch.setattr(web_inspection_service, "purge_expired_events", lambda db_conn: None)

    groups = web_inspection_service.get_device_evidence_groups(
        conn,
        device_ip="10.0.0.5",
        organization_id="default-org-id",
        limit=10,
    )

    assert len(groups) == 2
    first = groups[0]
    second = groups[1]

    assert first["group_key"] == "10.0.0.5|google chrome|chrome.exe|https://example.com/tab-1"
    assert first["event_count"] == 3
    assert first["request_bytes"] == 150
    assert first["response_bytes"] == 225
    assert first["risk_level"] == "high"
    assert first["confidence_score"] == 0.9
    assert first["page_urls"] == ["https://example.com/tab-1"]
    assert first["search_queries"] == ["alpha"]
    assert first["first_seen"] == "2026-04-26 01:00:00"
    assert first["last_seen"] == "2026-04-26 01:00:07"

    assert second["group_label"] == "Example Two"
    assert second["risk_level"] == "safe"
    assert second["event_count"] == 1
    assert second["page_urls"] == ["https://example.com/tab-2"]
