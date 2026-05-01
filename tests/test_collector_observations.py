from __future__ import annotations

from scapy.all import Ether, IP, TCP  # type: ignore

from shared.collector import (
    DpiObservation,
    FlowManager,
    FlowObservation,
    LinuxRawSocketCaptureBackend,
    PacketObservation,
    ScapyCaptureBackend,
    build_capture_backend,
)
import shared.collector.capture as capture_module


def test_packet_observation_round_trip_to_flow_observation():
    packet = Ether() / IP(src="10.0.0.10", dst="8.8.8.8") / TCP(sport=12345, dport=443)
    packet.captured_domain = "example.com"
    packet.captured_sni = "example.com"

    observation = PacketObservation.from_packet(packet, source_type="gateway", metadata_only=True)

    assert observation is not None
    assert observation.flow_key == ("10.0.0.10", "8.8.8.8", 12345, 443, "TCP")
    assert observation.domain == "example.com"
    assert observation.metadata_only is True
    assert observation.application_protocol == "HTTPS"
    assert observation.analysis_source == "port_signature"

    flow = observation.to_flow_observation(agent_id="GW-1", organization_id="ORG-1")
    assert isinstance(flow, FlowObservation)
    assert flow.source_type == "gateway"
    assert flow.metadata_only is True
    assert flow.domain == "example.com"
    assert flow.application_protocol == "HTTPS"
    assert flow.analysis_source == "port_signature"
    assert flow.agent_id == "GW-1"
    assert flow.organization_id == "ORG-1"


def test_flow_manager_status_snapshot_reports_capture_mode():
    manager = FlowManager(
        agent_id="GW-1",
        organization_id="ORG-1",
        on_flow_expired=lambda summary: None,
        source_type="gateway",
        metadata_only=True,
        start_worker=False,
    )

    snapshot = manager.status_snapshot()

    assert snapshot["source_type"] == "gateway"
    assert snapshot["metadata_only"] is True


def test_flow_manager_preserves_analyzer_metadata_in_summaries():
    manager = FlowManager(
        agent_id="GW-1",
        organization_id="ORG-1",
        on_flow_expired=lambda summary: None,
        source_type="gateway",
        metadata_only=True,
        start_worker=False,
    )
    observation = PacketObservation(
        observed_at=1_710_000_000.0,
        source_type="gateway",
        metadata_only=True,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=52100,
        dst_port=53,
        protocol="UDP",
        packet_size=128,
        domain="example.com",
        sni=None,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        application_protocol="DNS",
        service_name="dns",
        analysis_source="port_signature",
        analysis_confidence=1.0,
        analysis_signals=("port_signature", "dns_query"),
    )

    manager.update_from_observation(observation)
    state = manager._flows[observation.flow_key]
    summary = manager._build_summary(observation.flow_key, state)

    assert state.application_protocol == "DNS"
    assert state.service_name == "dns"
    assert state.analysis_source == "port_signature"
    assert state.analysis_confidence == 1.0
    assert state.analysis_signals == ("port_signature", "dns_query")
    assert summary.application_protocol == "DNS"
    assert summary.service_name == "dns"
    assert summary.analysis_source == "port_signature"
    assert summary.analysis_confidence == 1.0
    assert summary.analysis_signals == ("port_signature", "dns_query")


def test_build_capture_backend_prefers_linux_raw_on_linux(monkeypatch):
    monkeypatch.setattr(capture_module.platform, "system", lambda: "Linux")

    backend = build_capture_backend(role="gateway", interface="eth0", requested_backend="auto")

    assert isinstance(backend, LinuxRawSocketCaptureBackend)
    assert backend.backend_name == "linux_raw"


def test_build_capture_backend_uses_scapy_on_windows(monkeypatch):
    monkeypatch.setattr(capture_module.platform, "system", lambda: "Windows")

    backend = build_capture_backend(role="agent", interface=None, requested_backend="auto")

    assert isinstance(backend, ScapyCaptureBackend)
    assert backend.backend_name == "scapy"


def test_dpi_observation_payload_omits_raw_headers():
    observation = DpiObservation(
        browser_name="Chrome",
        process_name="chrome.exe",
        page_url="https://example.com",
        base_domain="example.com",
        page_title="Example",
        content_category="web",
        content_id=None,
        search_query=None,
        http_method="GET",
        status_code=200,
        content_type="text/html",
        request_bytes=123,
        response_bytes=456,
        snippet_redacted="hello",
        timestamp="2026-04-24T00:00:00Z",
        app="Chrome",
    )

    payload = observation.to_payload()

    assert payload["browser_name"] == "Chrome"
    assert payload["source_type"] == "agent"
    assert "headers" not in payload
