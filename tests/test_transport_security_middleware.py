from __future__ import annotations

import asyncio
from types import SimpleNamespace

from fastapi.responses import Response

import app.middleware.transport_security as transport_security_module


class _FakeMetrics:
    def __init__(self):
        self.calls = []

    def increment(self, name, amount=1, **labels):
        self.calls.append(("increment", name, amount, labels))


def _request(*, client_host: str, hostname: str, scheme: str = "http", path: str = "/api/v1/collect/register"):
    return SimpleNamespace(
        client=SimpleNamespace(host=client_host),
        headers={},
        url=SimpleNamespace(path=path, hostname=hostname, scheme=scheme),
    )


def test_private_lan_http_is_rejected_by_default(monkeypatch):
    fake_metrics = _FakeMetrics()
    monkeypatch.setattr(transport_security_module, "metrics_service", fake_metrics)
    monkeypatch.setattr(transport_security_module.settings, "ALLOW_LAN_HTTP", False)

    middleware = transport_security_module.TransportSecurityMiddleware(app=lambda scope, receive, send: None)
    request = _request(client_host="10.159.79.96", hostname="10.159.79.96")

    called = False

    async def call_next(_request):
        nonlocal called
        called = True
        return Response(status_code=200)

    response = asyncio.run(middleware.dispatch(request, call_next))

    assert response.status_code == 403
    assert called is False
    assert any(call[1] == "transport_https_rejections_total" for call in fake_metrics.calls)


def test_private_lan_http_is_allowed_when_opt_in_enabled(monkeypatch):
    fake_metrics = _FakeMetrics()
    monkeypatch.setattr(transport_security_module, "metrics_service", fake_metrics)
    monkeypatch.setattr(transport_security_module.settings, "ALLOW_LAN_HTTP", True)

    middleware = transport_security_module.TransportSecurityMiddleware(app=lambda scope, receive, send: None)
    request = _request(client_host="10.159.79.96", hostname="10.159.79.96")

    async def call_next(_request):
        return Response(status_code=200)

    response = asyncio.run(middleware.dispatch(request, call_next))

    assert response.status_code == 200
    assert fake_metrics.calls == []
