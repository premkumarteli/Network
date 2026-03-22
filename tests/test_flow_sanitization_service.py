from types import SimpleNamespace

from app.services.flow_sanitization_service import flow_sanitization_service


def test_sanitize_flow_maps_egress_traffic_to_internal_device_and_external_endpoint():
    flow = SimpleNamespace(
        src_ip="10.128.88.96",
        dst_ip="142.250.183.14",
        src_port=51523,
        dst_port=443,
        protocol="tcp",
        start_time="2026-03-21T10:00:00Z",
        last_seen="2026-03-21T10:00:05Z",
        packet_count=5,
        byte_count=5000,
        duration=5.0,
        average_packet_size=1000.0,
        domain="www.youtube.com",
        sni=None,
        agent_id="AGENT-1",
        source_type="gateway",
        metadata_only=True,
        src_mac="AA-BB-CC-DD-EE-FF",
        dst_mac="00:11:22:33:44:55",
    )

    sanitized = flow_sanitization_service.sanitize_flow(flow, organization_id="default-org-id")

    assert sanitized is not None
    assert sanitized.network_scope == "egress"
    assert sanitized.internal_device_ip == "10.128.88.96"
    assert sanitized.internal_device_mac == "aa:bb:cc:dd:ee:ff"
    assert sanitized.external_endpoint_ip == "142.250.183.14"
    assert sanitized.domain == "www.youtube.com"


def test_sanitize_flow_drops_control_plane_or_broadcast_traffic():
    flow = SimpleNamespace(
        src_ip="10.128.88.96",
        dst_ip="224.0.0.251",
        src_port=5353,
        dst_port=5353,
        protocol="udp",
        start_time="2026-03-21T10:00:00Z",
        last_seen="2026-03-21T10:00:01Z",
        packet_count=1,
        byte_count=120,
        duration=1.0,
        average_packet_size=120.0,
        domain=None,
        sni=None,
        agent_id="AGENT-1",
        source_type="gateway",
        metadata_only=True,
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="01:00:5e:00:00:fb",
    )

    assert flow_sanitization_service.sanitize_flow(flow, organization_id="default-org-id") is None
