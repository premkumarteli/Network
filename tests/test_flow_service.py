from types import SimpleNamespace
import asyncio
import json

import pytest

from app.services import flow_service as flow_service_module
from app.services.flow_service import FlowQueueBackpressureError, flow_service


def test_agent_flows_are_always_managed():
    flow = SimpleNamespace(source_type="agent", src_ip="10.0.0.10")
    assert flow_service.classify_management_mode(flow, set()) == "managed"


def test_gateway_flows_default_to_byod_when_ip_is_unknown():
    flow = SimpleNamespace(source_type="gateway", src_ip="10.0.0.10")
    assert flow_service.classify_management_mode(flow, {"10.0.0.11"}) == "byod"


def test_gateway_flows_use_internal_device_ip_for_management_mode():
    flow = SimpleNamespace(
        source_type="gateway",
        src_ip="203.0.113.5",
        internal_device_ip="10.0.0.10",
    )
    assert flow_service.classify_management_mode(flow, {"10.0.0.10"}) == "managed"


def test_alert_breakdown_carries_privacy_and_classification_context():
    breakdown = flow_service.build_alert_breakdown(
        {"breakdown": {"ml_score": 0.9}, "reasons": ["ML Anomaly Detected"]},
        management_mode="byod",
        source_type="gateway",
        metadata_only=True,
    )
    assert breakdown["management_mode"] == "byod"
    assert breakdown["source_type"] == "gateway"
    assert breakdown["metadata_only"] is True
    assert breakdown["reasons"] == ["ML Anomaly Detected"]


class _FakeCursor:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []

    def execute(self, query, params=None):
        self.calls.append((query, params))

    def fetchone(self):
        if self.rows:
            return self.rows.pop(0)
        return None


def test_flow_org_id_is_normalized_to_existing_single_org(monkeypatch):
    monkeypatch.setattr(flow_service_module.settings, "SINGLE_ORG_MODE", True)
    monkeypatch.setattr(flow_service_module.settings, "DEFAULT_ORGANIZATION_ID", "default-org-id")
    cursor = _FakeCursor([{"id": "real-org-id"}])

    resolved = flow_service._resolve_organization_id(cursor, "default-org-id", {})

    assert resolved == "real-org-id"
    assert cursor.calls == [("SELECT id FROM organizations LIMIT 1", None)]


def test_flow_org_id_becomes_null_when_unknown_in_multi_org_mode(monkeypatch):
    monkeypatch.setattr(flow_service_module.settings, "SINGLE_ORG_MODE", False)
    cursor = _FakeCursor([None])

    resolved = flow_service._resolve_organization_id(cursor, "missing-org-id", {})

    assert resolved is None
    assert cursor.calls == [("SELECT id FROM organizations WHERE id = %s LIMIT 1", ("missing-org-id",))]


class _QueueCursor:
    def __init__(self, conn, dictionary=False):
        self.conn = conn
        self.dictionary = dictionary

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO flow_ingest_batches"):
            self.conn.rows.append(
                {
                    "source_type": params[0],
                    "source_id": params[1],
                    "organization_id": params[2],
                    "batch_id": params[3],
                    "batch_json": params[4],
                    "flow_count": params[5],
                }
            )
            return
        raise AssertionError(f"Unexpected query: {normalized}")

    def close(self):
        return None


class _QueueConnection:
    def __init__(self):
        self.rows = []
        self.closed = False
        self.committed = False
        self.rolled_back = False

    def cursor(self, dictionary=False):
        return _QueueCursor(self, dictionary=dictionary)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_buffer_flow_updates_queue_metrics(monkeypatch):
    conn = _QueueConnection()
    item = SimpleNamespace(
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=443,
        protocol="TCP",
        domain="example.com",
        sni="example.com",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:AA:BB",
        packet_count=5,
        byte_count=500,
        duration=1.0,
        agent_id="AGENT-1",
        organization_id="org-1",
        start_time="2026-04-18T00:00:00Z",
        last_seen="2026-04-18T00:00:01Z",
        average_packet_size=100.0,
        source_type="agent",
        metadata_only=False,
    )

    monkeypatch.setattr(flow_service_module, "get_db_connection", lambda: conn)
    monkeypatch.setattr(flow_service, "_ensure_processing_ready", lambda db_conn: None)
    monkeypatch.setattr(flow_service, "_enforce_backpressure", lambda db_conn, incoming_flows: None)
    monkeypatch.setattr(
        flow_service,
        "_refresh_queue_depth",
        lambda db_conn=None: flow_service._set_metric("queue_depth", len(conn.rows)),
    )

    assert asyncio.run(flow_service.buffer_flow(item)) is True

    snapshot = flow_service.metrics_snapshot()

    assert snapshot["buffered_flows_total"] >= 1
    assert snapshot["queue_depth"] >= 1
    assert conn.committed is True
    assert conn.closed is True
    assert len(conn.rows) == 1
    assert len(conn.rows[0]["batch_id"]) == 64


def test_batch_id_is_stable_for_equivalent_payloads():
    payloads = [
        {"src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "packet_count": 5},
        {"dst_ip": "1.1.1.1", "src_ip": "10.0.0.11", "packet_count": 7},
    ]

    payload_json_a = flow_service._payload_json(payloads)
    payload_json_b = flow_service._payload_json([dict(item) for item in payloads])

    assert payload_json_a == payload_json_b
    assert flow_service._batch_id_from_payload_json(payload_json_a) == flow_service._batch_id_from_payload_json(payload_json_b)


class _BaselineCursor:
    def __init__(self):
        self.calls = []

    def execute(self, query, params=None):
        self.calls.append((" ".join(query.split()), params))

    def fetchall(self):
        return [
            {"device_id": "10.0.0.10", "avg_connections_per_min": 4.0},
            {"device_id": "10.0.0.11", "avg_connections_per_min": 2.0},
        ]


def test_device_baselines_are_loaded_in_one_batch_query():
    cursor = _BaselineCursor()

    baselines = flow_service._load_device_baselines(cursor, {"10.0.0.11", "10.0.0.10", ""})

    assert set(baselines) == {"10.0.0.10", "10.0.0.11"}
    assert len(cursor.calls) == 1
    query, params = cursor.calls[0]
    assert query == "SELECT * FROM device_baselines WHERE device_id IN (%s, %s)"
    assert params == ("10.0.0.10", "10.0.0.11")


def test_alert_dedupe_key_groups_same_device_detection():
    sanitized = SimpleNamespace(internal_device_ip="10.0.0.10")
    report = {
        "severity": "HIGH",
        "primary_detection": "Possible C2 Beaconing",
        "reasons": ["Possible C2 Beaconing"],
    }

    first = flow_service._alert_dedupe_key("org-1", sanitized, report)
    second = flow_service._alert_dedupe_key("org-1", sanitized, dict(report))
    different = flow_service._alert_dedupe_key(
        "org-1",
        sanitized,
        {"severity": "HIGH", "primary_detection": "Port Scanning Detected", "reasons": ["Port Scanning Detected"]},
    )

    assert first == second
    assert first != different


def test_buffer_flow_raises_backpressure_when_queue_depth_is_exceeded(monkeypatch):
    conn = _QueueConnection()
    item = SimpleNamespace(
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=443,
        protocol="TCP",
        domain="example.com",
        sni="example.com",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:AA:BB",
        packet_count=5,
        byte_count=500,
        duration=1.0,
        agent_id="AGENT-1",
        organization_id="org-1",
        start_time="2026-04-18T00:00:00Z",
        last_seen="2026-04-18T00:00:01Z",
        average_packet_size=100.0,
        source_type="agent",
        metadata_only=False,
    )

    monkeypatch.setattr(flow_service_module, "get_db_connection", lambda: conn)
    monkeypatch.setattr(flow_service, "_ensure_processing_ready", lambda db_conn: None)
    monkeypatch.setattr(
        flow_service,
        "_queue_status_counts",
        lambda db_conn=None: {
            "pending_batches": 1,
            "pending_flows": 5,
            "processing_batches": 0,
            "processing_flows": 0,
            "processed_batches": 0,
            "deadletter_batches": 0,
            "oldest_pending_age_seconds": 0,
            "active_workers": 0,
        },
    )
    monkeypatch.setattr(flow_service, "_refresh_queue_depth", lambda db_conn=None: None)
    monkeypatch.setattr(flow_service_module.settings, "FLOW_INGEST_MAX_PENDING_FLOWS", 5)
    monkeypatch.setattr(flow_service_module.settings, "FLOW_INGEST_MAX_LAG_SECONDS", 30)

    with pytest.raises(FlowQueueBackpressureError):
        asyncio.run(flow_service.buffer_flow(item))

    assert conn.rolled_back is True


def test_deserialize_batch_rehydrates_flow_models():
    queue_record = {
        "batch_json": json.dumps(
            [
                {
                    "src_ip": "10.0.0.10",
                    "dst_ip": "8.8.8.8",
                    "src_port": 12345,
                    "dst_port": 443,
                    "protocol": "tcp",
                    "domain": "example.com",
                    "sni": "example.com",
                    "src_mac": "00:11:22:33:44:55",
                    "dst_mac": "66:77:88:99:AA:BB",
                    "packet_count": 10,
                    "byte_count": 1200,
                    "duration": 1.25,
                    "agent_id": "AGENT-1",
                    "organization_id": "org-1",
                    "start_time": "2026-04-18T00:00:00Z",
                    "last_seen": "2026-04-18T00:00:01Z",
                    "average_packet_size": 120.0,
                    "source_type": "agent",
                    "metadata_only": False,
                }
            ]
        )
    }

    hydrated = flow_service._deserialize_batch(queue_record)

    assert len(hydrated) == 1
    assert hydrated[0].agent_id == "AGENT-1"
    assert hydrated[0].protocol == "TCP"

