from __future__ import annotations

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

    try:
        client._enforce_transport_policy("https://example.com/api/v1/collect/register")
        assert False, "Expected remote HTTPS without pins to be rejected"
    except requests.exceptions.SSLError as exc:
        assert "require configured TLS pins" in str(exc)


def test_local_http_is_allowed_without_pins(tmp_path):
    client = _client(tmp_path)

    client._enforce_transport_policy("http://127.0.0.1:8000/api/v1/collect/register")
