from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.middleware.csrf_protection import CSRFProtectionError, validate_csrf_request


def _request(*, method="POST", path="/mutate", cookies=None, headers=None):
    return SimpleNamespace(
        method=method,
        url=SimpleNamespace(path=path),
        cookies=cookies or {},
        headers=headers or {},
    )


def test_csrf_validation_allows_requests_without_session_cookie(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(settings, "CSRF_COOKIE_NAME", "XSRF-TOKEN")
    monkeypatch.setattr(settings, "CSRF_HEADER_NAME", "X-XSRF-TOKEN")

    validate_csrf_request(_request())


def test_csrf_validation_rejects_missing_header_with_session_cookie(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(settings, "CSRF_COOKIE_NAME", "XSRF-TOKEN")
    monkeypatch.setattr(settings, "CSRF_HEADER_NAME", "X-XSRF-TOKEN")

    with pytest.raises(CSRFProtectionError):
        validate_csrf_request(
            _request(
                cookies={
                    "netvisor_session": "session-token",
                    "XSRF-TOKEN": "csrf-token",
                }
            )
        )


def test_csrf_validation_accepts_matching_header(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_COOKIE_NAME", "netvisor_session")
    monkeypatch.setattr(settings, "CSRF_COOKIE_NAME", "XSRF-TOKEN")
    monkeypatch.setattr(settings, "CSRF_HEADER_NAME", "X-XSRF-TOKEN")

    validate_csrf_request(
        _request(
            cookies={
                "netvisor_session": "session-token",
                "XSRF-TOKEN": "csrf-token",
            },
            headers={"X-XSRF-TOKEN": "csrf-token"},
        )
    )
