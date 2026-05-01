from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core import dependencies


def _request(path: str = "/api/v1/auth/login", host: str = "127.0.0.1"):
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        url=SimpleNamespace(path=path),
        headers={},
    )


def test_request_rate_limit_blocks_after_limit(monkeypatch):
    dependency = dependencies.request_rate_limit(limit=2, window_seconds=60, bucket="test_limit")
    dependencies._rate_limit_buckets.clear()

    request = _request()
    dependency(request)
    dependency(request)
    with pytest.raises(HTTPException, match="Too many requests"):
        dependency(request)


def test_request_rate_limit_uses_custom_identity():
    dependency = dependencies.request_rate_limit(
        limit=1,
        window_seconds=60,
        bucket="test_agent_limit",
        key_builder=lambda request: request.headers.get("X-Agent-Id") or "anonymous",
    )
    dependencies._rate_limit_buckets.clear()

    request_a = _request(path="/api/v1/collect/heartbeat", host="10.0.0.2")
    request_a.headers = {"X-Agent-Id": "AGENT-A"}
    request_b = _request(path="/api/v1/collect/heartbeat", host="10.0.0.2")
    request_b.headers = {"X-Agent-Id": "AGENT-B"}

    dependency(request_a)
    dependency(request_b)
