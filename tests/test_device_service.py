from datetime import datetime, timedelta, timezone

from app.services.device_service import device_service


def test_trackable_device_ip_filters_remote_and_invalid_hosts():
    assert device_service._is_trackable_device_ip("10.128.88.172") is True
    assert device_service._is_trackable_device_ip("192.168.1.24") is True
    assert device_service._is_trackable_device_ip("116.119.225.34") is False
    assert device_service._is_trackable_device_ip("127.0.0.1") is False
    assert device_service._is_trackable_device_ip("224.0.0.1") is False
    assert device_service._is_trackable_device_ip("not-an-ip") is False


def test_merge_devices_prefers_managed_and_named_rows():
    devices = [
        {
            "ip": "10.128.88.172",
            "hostname": "Unknown",
            "management_mode": "byod",
            "confidence": "medium",
            "last_seen": "2026-03-20 08:00:00",
        },
        {
            "ip": "10.128.88.172",
            "hostname": "STUDENT-LAPTOP",
            "management_mode": "managed",
            "confidence": "high",
            "last_seen": "2026-03-20 08:00:01",
        },
    ]

    merged = device_service._merge_devices(devices)

    assert len(merged) == 1
    assert merged[0]["management_mode"] == "managed"
    assert merged[0]["hostname"] == "STUDENT-LAPTOP"


def test_device_status_uses_online_idle_offline_thresholds():
    now = datetime.now(timezone.utc)

    assert device_service.get_device_status(now - timedelta(seconds=5)) == "Online"
    assert device_service.get_device_status(now - timedelta(seconds=30)) == "Idle"
    assert device_service.get_device_status(now - timedelta(seconds=90)) == "Offline"

