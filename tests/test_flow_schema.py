import pytest
from pydantic import ValidationError

from app.schemas.flow_schema import FlowBase


def sample_flow(**overrides):
    payload = {
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "src_port": 51000,
        "dst_port": 53,
        "protocol": "udp",
        "packet_count": 4,
        "byte_count": 512,
        "duration": 1.5,
        "agent_id": "AGENT-TEST01",
        "organization_id": "org-1",
        "start_time": "2026-03-17T00:00:00Z",
        "last_seen": "2026-03-17T00:00:02Z",
        "average_packet_size": 128.0,
    }
    payload.update(overrides)
    return payload


def test_flow_schema_rejects_unexpected_payload_field():
    with pytest.raises(ValidationError):
        FlowBase(**sample_flow(payload="secret"))


def test_flow_schema_normalizes_protocol():
    flow = FlowBase(**sample_flow(protocol="tcp"))
    assert flow.protocol == "TCP"


def test_flow_schema_accepts_optional_sni():
    flow = FlowBase(**sample_flow(sni="chat.openai.com"))
    assert flow.sni == "chat.openai.com"

