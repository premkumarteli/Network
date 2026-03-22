from datetime import datetime, timedelta, timezone

from app.services.agent_service import agent_service


def test_build_agent_entry_marks_recent_heartbeat_online():
    entry = agent_service._build_agent_entry(
        {
            "agent_id": "AGENT-1",
            "hostname": "NODE-1",
            "ip_address": "10.0.0.5",
            "last_seen": datetime.now(timezone.utc) - timedelta(seconds=20),
            "os_family": "Windows",
            "version": "v3.0-hybrid",
        },
        device_count=4,
    )

    assert entry["agent_id"] == "AGENT-1"
    assert entry["status"] == "Online"
    assert entry["device_count"] == 4
    assert entry["heartbeat_age_seconds"] is not None


def test_build_agent_entry_marks_stale_heartbeat_offline():
    entry = agent_service._build_agent_entry(
        {
            "agent_id": "AGENT-2",
            "hostname": "NODE-2",
            "ip_address": "10.0.0.9",
            "last_seen": datetime.now(timezone.utc) - timedelta(minutes=5),
        },
        device_count=1,
        online_window_seconds=90,
    )

    assert entry["status"] == "Offline"


def test_build_agent_entry_includes_inspection_state():
    entry = agent_service._build_agent_entry(
        {
            "agent_id": "AGENT-3",
            "hostname": "NODE-3",
            "ip_address": "10.0.0.10",
            "last_seen": datetime.now(timezone.utc),
            "inspection_enabled": True,
            "inspection_status": "running",
            "inspection_proxy_running": True,
            "inspection_ca_installed": True,
            "inspection_browsers_json": '["chrome.exe","msedge.exe"]',
            "inspection_last_error": None,
        },
        device_count=2,
    )

    assert entry["inspection_enabled"] is True
    assert entry["inspection_status"] == "running"
    assert entry["inspection_proxy_running"] is True
    assert entry["inspection_ca_installed"] is True
    assert entry["inspection_browsers"] == ["chrome.exe", "msedge.exe"]


def test_merge_device_rows_prefers_managed_endpoint_for_duplicate_ip():
    devices = agent_service._merge_device_rows(
        [
            {
                "ip": "10.128.88.96",
                "hostname": "ADMIN-PC",
                "management_mode": "managed",
                "last_seen": "2026-03-20 10:00:00",
            }
        ],
        [
            {
                "ip": "10.128.88.96",
                "hostname": "Unknown",
                "management_mode": "observed",
                "last_seen": "2026-03-20 09:59:00",
            }
        ],
    )

    assert len(devices) == 1
    assert devices[0]["management_mode"] == "managed"
    assert devices[0]["hostname"] == "ADMIN-PC"

