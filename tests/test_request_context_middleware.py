from __future__ import annotations

import asyncio
from types import SimpleNamespace

from starlette.responses import Response

import app.middleware.request_context as request_context_module


class _FakeMetrics:
    def __init__(self):
        self.calls = []

    def increment(self, name, amount=1, **labels):
        self.calls.append(("increment", name, amount, labels))

    def observe(self, name, value, **labels):
        self.calls.append(("observe", name, value, labels))


def test_request_context_middleware_sets_request_id_and_metrics(monkeypatch):
    fake_metrics = _FakeMetrics()
    monkeypatch.setattr(request_context_module, "metrics_service", fake_metrics)

    middleware = request_context_module.RequestContextMiddleware(app=lambda scope, receive, send: None)
    request = SimpleNamespace(
        method="GET",
        headers={"x-request-id": "req-123"},
        url=SimpleNamespace(path="/api/v1/health/status"),
        state=SimpleNamespace(),
    )

    async def call_next(_request):
        return Response(status_code=200)

    response = asyncio.run(middleware.dispatch(request, call_next))

    assert request.state.request_id == "req-123"
    assert response.headers["X-Request-ID"] == "req-123"
    assert ("increment", "http_requests_total", 1, {"method": "GET", "status_class": "2xx"}) in fake_metrics.calls
    assert any(call[0] == "observe" and call[1] == "http_request_duration_seconds" for call in fake_metrics.calls)
