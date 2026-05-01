from types import SimpleNamespace

from app.services.flow_sanitization_service import flow_sanitization_service


def test_flow_sanitization_tolerates_missing_timestamps():
    flow = SimpleNamespace(
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_count=5,
        byte_count=2000,
        start_time=None,
        last_seen=None,
    )
    sanitized = flow_sanitization_service.sanitize_flow(flow, organization_id="org-1")
    assert sanitized is not None
    assert sanitized.start_time is not None
    assert sanitized.last_seen is not None
