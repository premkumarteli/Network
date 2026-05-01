from __future__ import annotations

import asyncio

import pytest

from app.core.config import settings
from app.core.security import create_access_token
from app import realtime


class _FakeConn:
    def close(self):
        return None


class _FakeSocketServer:
    def __init__(self):
        self.calls = []

    async def emit(self, event_name, payload, room=None):
        self.calls.append((event_name, payload, room))


class _FakeMetrics:
    def __init__(self):
        self.calls = []

    def increment(self, name, amount=1, **labels):
        self.calls.append((name, amount, labels))


def test_authenticate_socket_connection_uses_auth_cookie(monkeypatch):
    monkeypatch.setattr(settings, "SECRET_KEY", "x" * 32)
    token = create_access_token("user-1")
    environ = {
        "HTTP_COOKIE": f"{settings.AUTH_COOKIE_NAME}={token}",
    }

    monkeypatch.setattr(realtime, "get_db_connection", lambda: _FakeConn())
    monkeypatch.setattr(realtime, "metrics_service", _FakeMetrics())
    monkeypatch.setattr(
        realtime.auth_service,
        "get_user_by_id",
        lambda conn, user_id: {
            "id": user_id,
            "role": "org_admin",
            "organization_id": "org-1",
            "status": "active",
        },
    )

    context = realtime.authenticate_socket_connection(environ)

    assert context["user_id"] == "user-1"
    assert context["organization_id"] == "org-1"
    assert context["role"] == "org_admin"


def test_authenticate_socket_connection_rejects_missing_cookie(monkeypatch):
    monkeypatch.setattr(realtime, "metrics_service", _FakeMetrics())

    with pytest.raises(realtime.SocketAuthenticationError):
        realtime.authenticate_socket_connection({})


def test_emit_event_targets_org_room(monkeypatch):
    server = _FakeSocketServer()
    realtime.configure_socket_server(server)

    asyncio.run(realtime.emit_event("packet_event", {"organization_id": "org-1", "src_ip": "10.0.0.10"}))

    assert server.calls == [("packet_event", {"organization_id": "org-1", "src_ip": "10.0.0.10"}, "org:org-1")]


def test_emit_event_defaults_to_authenticated_room(monkeypatch):
    server = _FakeSocketServer()
    realtime.configure_socket_server(server)

    asyncio.run(realtime.emit_event("alert_event", {"severity": "high"}))

    assert server.calls == [("alert_event", {"severity": "high"}, realtime.AUTHENTICATED_SOCKET_ROOM)]
