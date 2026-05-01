from __future__ import annotations

import pytest
import requests

from agent.security.dpapi import DataProtector
from agent.security.transport import AgentApiClient


class FakeProtector(DataProtector):
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data


def _client(tmp_path, *, pins=None) -> AgentApiClient:
    return AgentApiClient(
        state_path=tmp_path / "transport-state.json",
        bootstrap_api_key="bootstrap-key",
        protector=FakeProtector(),
        initial_pins=pins or [],
    )


def test_remote_backend_requires_https(tmp_path):
    client = _client(tmp_path)

    try:
        client._enforce_transport_policy("http://example.com/api/v1/collect/register")
        assert False, "Expected remote HTTP transport to be rejected"
    except requests.exceptions.SSLError as exc:
        assert "must use HTTPS" in str(exc)


def test_remote_https_requires_seed_pins(tmp_path):
    client = _client(tmp_path)

    with pytest.raises(requests.exceptions.SSLError, match="require configured TLS pins"):
        client._enforce_transport_policy("https://example.com/api/v1/collect/register")


def test_private_lan_http_requires_explicit_opt_in(tmp_path):
    client = _client(tmp_path)

    with pytest.raises(requests.exceptions.SSLError, match="must use HTTPS"):
        client._enforce_transport_policy("http://10.159.79.96:8000/api/v1/collect/register")


def test_local_http_is_allowed_without_pins(tmp_path):
    client = _client(tmp_path)

    client._enforce_transport_policy("http://127.0.0.1:8000/api/v1/collect/register")


def test_private_lan_http_is_allowed_when_opt_in_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("NETVISOR_ALLOW_LAN_HTTP", "true")
    client = _client(tmp_path)

    client._enforce_transport_policy("http://10.159.79.96:8000/api/v1/collect/register")
