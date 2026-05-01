from datetime import datetime, timezone

from app.services.analytics_service import analytics_service
from app.services.application_service import application_service
from app.services.flow_service import flow_service


class DummyConn:
    pass


def test_get_overview_includes_rollups_and_summary(monkeypatch):
    monkeypatch.setattr(analytics_service, "ensure_schema", lambda *_: None)
    monkeypatch.setattr(
        analytics_service,
        "_device_lookup",
        lambda *args, **kwargs: {
            "10.0.0.10": {
                "hostname": "DESKTOP-IFIA9GL",
                "status": "Online",
                "management_mode": "managed",
            }
        },
    )
    monkeypatch.setattr(
        analytics_service,
        "_fetch_device_rollup",
        lambda *args, **kwargs: [
            {
                "device_ip": "10.0.0.10",
                "flow_count": 5,
                "bandwidth_bytes": 2048,
                "distinct_targets": 2,
                "last_seen": datetime(2026, 4, 26, 1, 0, 0, tzinfo=timezone.utc),
            }
        ],
    )
    monkeypatch.setattr(
        analytics_service,
        "_fetch_device_application_rollup",
        lambda *args, **kwargs: {
            "10.0.0.10": {
                "application": "ChatGPT",
                "bandwidth_bytes": 1536,
                "flow_count": 3,
            }
        },
    )
    monkeypatch.setattr(
        analytics_service,
        "_fetch_conversation_rollup",
        lambda *args, **kwargs: [
            {
                "src_ip": "10.0.0.10",
                "dst_ip": "1.1.1.1",
                "host": "chat.openai.com",
                "application": "ChatGPT",
                "protocol": "TCP",
                "flow_count": 3,
                "bandwidth_bytes": 1536,
                "last_seen": datetime(2026, 4, 26, 1, 0, 0, tzinfo=timezone.utc),
            }
        ],
    )
    monkeypatch.setattr(
        analytics_service,
        "_fetch_scope_rollup",
        lambda *args, **kwargs: [
            {
                "network_scope": "internal_lan",
                "flow_count": 5,
                "device_count": 1,
                "bandwidth_bytes": 2048,
                "last_seen": datetime(2026, 4, 26, 1, 0, 0, tzinfo=timezone.utc),
            }
        ],
    )
    monkeypatch.setattr(
        analytics_service,
        "_fetch_trend_rollup",
        lambda *args, **kwargs: [
            {
                "bucket": "2026-04-26 01:00:00",
                "flow_count": 5,
                "device_count": 1,
                "bandwidth_bytes": 2048,
            }
        ],
    )
    monkeypatch.setattr(
        analytics_service,
        "_fetch_window_summary",
        lambda *args, **kwargs: {
            "flow_count": 5,
            "device_count": 1,
            "host_count": 2,
            "bandwidth_bytes": 2048,
        },
    )
    monkeypatch.setattr(
        application_service,
        "get_application_summary",
        lambda *args, **kwargs: [
            {
                "application": "ChatGPT",
                "device_count": 1,
                "active_device_count": 1,
                "bandwidth_bytes": 1536,
                "bandwidth": "1.5 KB",
                "runtime_seconds": 120,
                "runtime": "2m 0s",
                "last_seen": "2026-04-26 01:00:00",
            }
        ],
    )
    monkeypatch.setattr(
        application_service,
        "get_top_other_domains",
        lambda *args, **kwargs: [
            {
                "host": "unknown.example.org",
                "base_domain": "example.org",
                "flow_count": 2,
                "bandwidth_bytes": 128,
                "last_seen": "2026-04-26 00:59:00",
            }
        ],
    )

    overview = analytics_service.get_overview(DummyConn(), organization_id="default-org-id", hours=24, limit=5)

    assert overview["summary"]["flow_count"] == 5
    assert overview["summary"]["observed_device_count"] == 1
    assert overview["summary"]["fleet_device_count"] == 1
    assert overview["summary"]["top_application"] == "ChatGPT"
    assert overview["summary"]["top_conversation"] == "10.0.0.10 -> 1.1.1.1"
    assert overview["top_devices"][0]["hostname"] == "DESKTOP-IFIA9GL"
    assert overview["top_devices"][0]["top_application"] == "ChatGPT"
    assert overview["traffic_scopes"][0]["network_scope"] == "internal_lan"
    assert overview["uncategorized_domains"][0]["base_domain"] == "example.org"


def test_export_dataset_renders_flow_csv(monkeypatch):
    monkeypatch.setattr(analytics_service, "ensure_schema", lambda *_: None)
    monkeypatch.setattr(
        flow_service,
        "get_flow_logs",
        lambda *args, **kwargs: {
            "results": [
                {
                    "id": 1,
                    "src_ip": "10.0.0.10",
                    "dst_ip": "1.1.1.1",
                    "application": "ChatGPT",
                    "byte_count": 1234,
                    "last_seen": datetime(2026, 4, 26, 1, 0, 0, tzinfo=timezone.utc),
                }
            ]
        },
    )

    bundle = analytics_service.export_dataset(
        DummyConn(),
        kind="flows",
        organization_id="default-org-id",
        limit=100,
        src_ip="10.0.0.10",
    )

    assert bundle["filename"] == "netvisor-flow-logs.csv"
    assert "src_ip,dst_ip,application" in bundle["content"].splitlines()[0]
    assert "ChatGPT" in bundle["content"]
    assert "2026-04-26 01:00:00" in bundle["content"]
