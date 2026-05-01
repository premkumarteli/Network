from __future__ import annotations

import pytest
import asyncio
from types import SimpleNamespace

from fastapi import HTTPException, Response

from app.api import auth as auth_api
from app.core import dependencies
from app.core.config import settings
from app.core.security import create_access_token


class _Connection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _run(awaitable):
    return asyncio.run(awaitable)


def _set_cookie_headers(response: Response) -> str:
    values = [
        value.decode("latin-1")
        for key, value in getattr(response.headers, "raw", [])
        if key.lower() == b"set-cookie"
    ]
    return "\n".join(values)


def test_login_sets_http_only_session_cookie(monkeypatch):
    conn = _Connection()
    user = {
        "id": "user-1",
        "username": "alice",
        "email": "alice@example.com",
        "role": "org_admin",
        "organization_id": "org-1",
    }

    monkeypatch.setattr(auth_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(auth_api.auth_service, "authenticate", lambda *_args: user)
    monkeypatch.setattr(auth_api.metrics_service, "increment", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_api.audit_service, "log_auth_attempt", lambda *args, **kwargs: None)
    monkeypatch.setattr(settings, "SECRET_KEY", "unit-test-secret-key-123")
    monkeypatch.setattr(settings, "ACCESS_TOKEN_MINUTES", 30)
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(settings, "AUTH_COOKIE_SAMESITE", "lax")
    monkeypatch.setattr(settings, "AUTH_COOKIE_SECURE", False)
    monkeypatch.setattr(settings, "AUTH_COOKIE_PATH", "/")
    monkeypatch.setattr(settings, "AUTH_COOKIE_DOMAIN", None)

    response = Response()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(scheme="http"),
    )
    form_data = SimpleNamespace(username="alice", password="secret123")

    payload = _run(auth_api.login(request, response, form_data, _rate_limited=True))

    assert payload["authenticated"] is True
    assert payload["username"] == "alice"
    cookie_header = _set_cookie_headers(response)
    assert "netvisor_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header
    assert "Path=/" in cookie_header
    assert "XSRF-TOKEN=" in cookie_header
    assert conn.closed is True


def test_logout_clears_session_cookie(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(settings, "AUTH_COOKIE_SAMESITE", "lax")
    monkeypatch.setattr(settings, "AUTH_COOKIE_SECURE", False)
    monkeypatch.setattr(settings, "AUTH_COOKIE_PATH", "/")
    monkeypatch.setattr(settings, "AUTH_COOKIE_DOMAIN", None)

    response = Response()
    request = SimpleNamespace(url=SimpleNamespace(scheme="http"))

    payload = _run(auth_api.logout(request, response))

    assert payload["status"] == "ok"
    cookie_header = _set_cookie_headers(response)
    assert "netvisor_session=" in cookie_header
    assert "Max-Age=0" in cookie_header
    assert "XSRF-TOKEN=" in cookie_header


def test_get_current_user_accepts_session_cookie(monkeypatch):
    conn = _Connection()
    user = {
        "id": "user-1",
        "username": "alice",
        "role": "viewer",
        "organization_id": "org-1",
        "status": "active",
        "locked_until": None,
    }

    monkeypatch.setattr(settings, "SECRET_KEY", "unit-test-secret-key-123")
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    monkeypatch.setattr(dependencies.auth_service, "get_user_by_id", lambda *_args: user)

    token = create_access_token("user-1")
    request = SimpleNamespace(cookies={"netvisor_session": token}, headers={})

    current_user = dependencies.get_current_user(request=request)

    assert current_user["id"] == "user-1"
    assert conn.closed is True


def test_get_current_user_rejects_bearer_only_token(monkeypatch):
    conn = _Connection()
    monkeypatch.setattr(settings, "SECRET_KEY", "unit-test-secret-key-123")
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    token = create_access_token("user-2")
    request = SimpleNamespace(cookies={}, headers={"Authorization": f"Bearer {token}"})

    with pytest.raises(HTTPException):
        dependencies.get_current_user(request=request)

    assert conn.closed is False
