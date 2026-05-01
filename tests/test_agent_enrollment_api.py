from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.api import agents as agent_api


class _RequestUrl:
    def __init__(self, path: str, query: str = ""):
        self.path = path
        self.query = query


class _Request:
    def __init__(self, *, method: str = "POST", path: str = "/api/v1/collect/register", headers: dict[str, str] | None = None):
        self.method = method
        self.url = _RequestUrl(path)
        self.headers = headers or {}
        self.query_params = {}
        self.client = SimpleNamespace(host="127.0.0.1")

    async def body(self) -> bytes:
        return b""


class _Cursor:
    def close(self):
        return None


class _Connection:
    def cursor(self, dictionary=False):
        return _Cursor()

    def commit(self):
        return None

    def rollback(self):
        return None

    def close(self):
        return None


class _IssuedCredential:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.key_version = 2
        self.secret = "signed-secret"
        self.issued_at = "2026-05-01 00:00:00"

    def as_response(self):
        return {
            "agent_id": self.agent_id,
            "key_version": self.key_version,
            "secret": self.secret,
            "issued_at": self.issued_at,
        }


@pytest.mark.anyio
async def test_register_agent_returns_pending_response_without_upserting_state(monkeypatch):
    conn = _Connection()
    request = _Request(headers={"X-Forwarded-For": "10.10.10.10", "X-API-Key": "bootstrap-key"})
    audit_calls = []
    upsert_calls = []
    device_calls = []
    touch_calls = []
    metric_calls = []

    monkeypatch.setattr(agent_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(agent_api, "_resolve_org_id", lambda cursor, requested_org_id: "org-1")
    monkeypatch.setattr(
        agent_api.agent_enrollment_service,
        "record_request",
        lambda *args, **kwargs: {
            "request": {
                "request_id": "request-1",
                "agent_id": "AGENT-1",
                "status": "pending_review",
                "attempt_count": 1,
            },
            "status_changed": True,
            "previous_status": None,
        },
    )
    monkeypatch.setattr(agent_api.agent_auth_service, "get_active_credential", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_api.agent_service, "upsert_agent", lambda *args, **kwargs: upsert_calls.append(kwargs))
    monkeypatch.setattr(agent_api.managed_device_service, "upsert_device", lambda *args, **kwargs: device_calls.append(kwargs))
    monkeypatch.setattr(agent_api.device_service, "touch_device_seen", lambda *args, **kwargs: touch_calls.append(kwargs))
    monkeypatch.setattr(
        agent_api.audit_service,
        "log_agent_registration",
        lambda *args, **kwargs: audit_calls.append(kwargs),
    )
    monkeypatch.setattr(
        agent_api.metrics_service,
        "increment",
        lambda name, amount=1, **labels: metric_calls.append((name, amount, labels)),
    )

    response = await agent_api.register_agent(
        request,
        reg={
            "agent_id": "AGENT-1",
            "hostname": "desk-1",
            "device_ip": "10.10.10.20",
            "device_mac": "aa:bb:cc:dd:ee:ff",
            "os": "Windows",
            "version": "v3.0-hybrid",
        },
    )

    assert response.status_code == 202
    payload = json.loads(response.body)
    assert payload["enrollment_status"] == "pending_review"
    assert payload["message"] == "Enrollment pending Fleet approval."
    assert payload["agent_credentials"] is None
    assert upsert_calls == []
    assert device_calls == []
    assert touch_calls == []
    assert any(call["action"] == "agent_enrollment_requested" for call in audit_calls)


@pytest.mark.anyio
async def test_register_agent_issues_credentials_after_approval(monkeypatch):
    conn = _Connection()
    request = _Request(headers={"X-Forwarded-For": "10.10.10.11", "X-API-Key": "bootstrap-key"})
    audit_calls = []
    upsert_calls = []
    device_calls = []
    touch_calls = []
    mark_calls = []
    metric_calls = []

    monkeypatch.setattr(agent_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(agent_api, "_resolve_org_id", lambda cursor, requested_org_id: "org-1")
    monkeypatch.setattr(
        agent_api.agent_enrollment_service,
        "record_request",
        lambda *args, **kwargs: {
            "request": {
                "request_id": "request-2",
                "agent_id": "AGENT-2",
                "status": "approved",
                "attempt_count": 1,
            },
            "status_changed": False,
            "previous_status": None,
        },
    )
    monkeypatch.setattr(agent_api.agent_auth_service, "get_active_credential", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        agent_api.agent_auth_service,
        "issue_initial_credential",
        lambda *args, **kwargs: _IssuedCredential("AGENT-2"),
    )
    monkeypatch.setattr(
        agent_api.agent_enrollment_service,
        "mark_credential_issued",
        lambda *args, **kwargs: mark_calls.append(kwargs),
    )
    monkeypatch.setattr(agent_api.agent_service, "upsert_agent", lambda *args, **kwargs: upsert_calls.append(kwargs))
    monkeypatch.setattr(agent_api.managed_device_service, "upsert_device", lambda *args, **kwargs: device_calls.append(kwargs))
    monkeypatch.setattr(agent_api.device_service, "touch_device_seen", lambda *args, **kwargs: touch_calls.append(kwargs))
    monkeypatch.setattr(
        agent_api.audit_service,
        "log_agent_registration",
        lambda *args, **kwargs: audit_calls.append(kwargs),
    )
    monkeypatch.setattr(
        agent_api.metrics_service,
        "increment",
        lambda name, amount=1, **labels: metric_calls.append((name, amount, labels)),
    )

    response = await agent_api.register_agent(
        request,
        reg={
            "agent_id": "AGENT-2",
            "hostname": "desk-2",
            "device_ip": "10.10.10.21",
            "device_mac": "aa:bb:cc:dd:ee:01",
            "os": "Windows",
            "version": "v3.0-hybrid",
        },
    )

    assert response["message"] == "Agent enrollment approved."
    assert response["agent_credentials"]["secret"] == "signed-secret"
    assert response["enrollment_status"] == "approved"
    assert len(upsert_calls) == 1
    assert len(device_calls) == 1
    assert len(touch_calls) == 1
    assert mark_calls and mark_calls[0]["agent_id"] == "AGENT-2"
    assert any(call["action"] == "agent_enrollment_completed" for call in audit_calls)
