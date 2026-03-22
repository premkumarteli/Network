from types import SimpleNamespace

from app.services import flow_service as flow_service_module
from app.services.flow_service import flow_service


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

