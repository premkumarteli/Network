from __future__ import annotations

from pathlib import Path
import tempfile

import pytest
import requests

from gateway.security.dpapi import DataProtector
from gateway.security.state import GatewayStateStore
from gateway.security.transport import GatewayApiClient


class FakeProtector(DataProtector):
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data


class FakeResponse:
    def __init__(self):
        self.closed = False
        self.raw = type("Raw", (), {"connection": type("Conn", (), {"sock": object()})()})()

    def close(self):
        self.closed = True


def _tmpdir() -> Path:
    base = Path.cwd() / "tmp"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="netvisor-gateway-transport-", dir=base))


def _client(tmp_dir: Path, *, pins=None) -> GatewayApiClient:
    store = GatewayStateStore(
        tmp_dir / "transport-state.bin",
        protector=FakeProtector(),
        platform_name="nt",
    )
    return GatewayApiClient(
        state_path=tmp_dir / "transport-state.bin",
        bootstrap_api_key="bootstrap-key",
        store=store,
        initial_pins=pins or [],
    )


def test_remote_backend_requires_https():
    client = _client(_tmpdir())

    try:
        client._enforce_transport_policy("http://example.com/api/v1/gateway/register")
        assert False, "Expected remote HTTP transport to be rejected"
    except requests.exceptions.SSLError as exc:
        assert "must use HTTPS" in str(exc)


def test_remote_https_requires_seed_pins():
    client = _client(_tmpdir())

    with pytest.raises(requests.exceptions.SSLError, match="require configured TLS pins"):
        client._enforce_transport_policy("https://example.com/api/v1/gateway/register")


def test_private_lan_http_requires_explicit_opt_in():
    client = _client(_tmpdir())

    with pytest.raises(requests.exceptions.SSLError, match="must use HTTPS"):
        client._enforce_transport_policy("http://10.159.79.96:8000/api/v1/gateway/register")


def test_local_http_is_allowed_without_pins():
    client = _client(_tmpdir())

    client._enforce_transport_policy("http://127.0.0.1:8000/api/v1/gateway/register")


def test_private_lan_http_is_allowed_when_opt_in_enabled(monkeypatch):
    monkeypatch.setenv("NETVISOR_ALLOW_LAN_HTTP", "true")
    client = _client(_tmpdir())

    client._enforce_transport_policy("http://10.159.79.96:8000/api/v1/gateway/register")


def test_remote_tls_pin_mismatch_is_rejected(monkeypatch):
    client = _client(
        _tmpdir(),
        pins=[{"pin_type": "cert_sha256", "pin_sha256": "A" * 64, "status": "active"}],
    )
    response = FakeResponse()

    monkeypatch.setattr(client, "_extract_peer_certificate", lambda _: b"fake-cert-der")
    monkeypatch.setattr(client, "_pin_fingerprint", lambda pin_type, certificate_der: "B" * 64)

    try:
        client._enforce_tls_pins("https://example.com/api/v1/gateway/register", response)
        assert False, "Expected TLS pin mismatch to be rejected"
    except requests.exceptions.SSLError as exc:
        assert "pin mismatch" in str(exc).lower()
    assert response.closed is True
