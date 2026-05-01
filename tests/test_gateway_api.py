from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api import gateway as gateway_api
from app.core.config import settings
from shared.security.agent_auth import sign_request
from app.services.flow_service import FlowQueueBackpressureError
from app.services.gateway_auth_service import gateway_auth_service
from app.schemas.flow_schema import FlowBase


class _RequestUrl:
    def __init__(self, path: str, query: str = ""):
        self.path = path
        self.query = query


class _Request:
    def __init__(self, *, method: str, path: str, headers: dict[str, str], body: bytes = b"", query: str = ""):
        self.method = method
        self.url = _RequestUrl(path, query)
        self.headers = headers
        self.query_params = {}
        self._body = body

    async def body(self) -> bytes:
        return self._body


class _Cursor:
    def __init__(self, conn, dictionary=False):
        self.conn = conn
        self.dictionary = dictionary
        self._result = None

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        if normalized == "SELECT id FROM organizations LIMIT 1":
            self._result = {"id": self.conn.default_org_id}
            return
        if normalized.startswith("SELECT organization_id FROM gateways WHERE gateway_id = %s LIMIT 1"):
            gateway_id = params[0]
            org_id = self.conn.gateway_orgs.get(gateway_id)
            self._result = {"organization_id": org_id} if org_id else None
            return
        if normalized.startswith("DELETE FROM gateway_request_nonces"):
            self._result = None
            return
        if normalized.startswith("INSERT INTO gateway_request_nonces"):
            key = (params[0], int(params[1]), params[2])
            if key in self.conn.nonces:
                raise ValueError("duplicate nonce")
            self.conn.nonces.add(key)
            self._result = None
            return
        if (
            "FROM gateway_credentials" in normalized
            and "WHERE gateway_id = %s AND key_version = %s" in normalized
            and "LIMIT 1" in normalized
        ):
            self._result = self.conn.credentials.get((params[0], int(params[1])))
            return
        if (
            "FROM gateway_credentials" in normalized
            and "WHERE gateway_id = %s AND status = 'active'" in normalized
            and "ORDER BY key_version DESC LIMIT 1" in normalized
        ):
            gateway_id = params[0]
            rows = [
                row
                for (stored_gateway_id, _), row in self.conn.credentials.items()
                if stored_gateway_id == gateway_id and row.get("status") == "active"
            ]
            rows.sort(key=lambda row: int(row["key_version"]), reverse=True)
            self._result = rows[0] if rows else None
            return
        if normalized.startswith("SELECT COALESCE(MAX(key_version), 0) AS max_version FROM gateway_credentials"):
            gateway_id = params[0]
            versions = [version for (stored_gateway_id, version) in self.conn.credentials if stored_gateway_id == gateway_id]
            self._result = {"max_version": max(versions) if versions else 0}
            return
        if normalized.startswith("INSERT INTO gateway_credentials"):
            gateway_id, key_version, secret_salt, secret_hash = params
            self.conn.credentials[(gateway_id, int(key_version))] = {
                "gateway_id": gateway_id,
                "key_version": int(key_version),
                "secret_salt": secret_salt,
                "secret_hash": secret_hash,
                "status": "active",
                "issued_at": datetime.now(timezone.utc),
            }
            self._result = None
            return
        if normalized.startswith("UPDATE gateway_credentials SET status = 'rotating'"):
            gateway_id = params[0]
            for (stored_gateway_id, _), row in self.conn.credentials.items():
                if stored_gateway_id == gateway_id and row.get("status") == "active":
                    row["status"] = "rotating"
            self._result = None
            return
        if normalized.startswith("UPDATE gateway_credentials SET status = 'rotated'"):
            gateway_id, key_version = params
            for (stored_gateway_id, stored_version), row in self.conn.credentials.items():
                if (
                    stored_gateway_id == gateway_id
                    and stored_version < int(key_version)
                    and row.get("status") in {"active", "rotating"}
                ):
                    row["status"] = "rotated"
            self._result = None
            return
        if normalized.startswith("UPDATE gateway_credentials SET last_used_at"):
            self.conn.last_used_updates.append((params[0], int(params[1])))
            self._result = None
            return
        raise AssertionError(f"Unexpected query: {normalized}")

    def fetchone(self):
        return self._result

    def close(self):
        return None


class _Connection:
    def __init__(self, *, default_org_id="default-org-id", credentials=None, gateway_orgs=None):
        self.default_org_id = default_org_id
        self.credentials = credentials or {}
        self.gateway_orgs = gateway_orgs or {}
        self.nonces = set()
        self.last_used_updates = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = 0

    def cursor(self, dictionary=False):
        return _Cursor(self, dictionary=dictionary)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed += 1


def _run(awaitable):
    return asyncio.run(awaitable)


def _seed_credential(monkeypatch, gateway_id: str, *, key_version: int = 1, secret_salt: str = "salt123"):
    monkeypatch.setattr(settings, "GATEWAY_MASTER_KEY", "unit-test-gateway-master-key")
    secret = gateway_auth_service._derive_secret(
        gateway_id=gateway_id,
        key_version=key_version,
        secret_salt=secret_salt,
    )
    row = {
        "gateway_id": gateway_id,
        "key_version": key_version,
        "secret_salt": secret_salt,
        "status": "active",
        "issued_at": datetime.now(timezone.utc),
    }
    return secret, row


def _signed_headers(*, secret: str, gateway_id: str, key_version: int, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{path.rsplit('/', 1)[-1]}"
    signature = sign_request(
        secret=secret,
        method="POST",
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return {
        "Content-Type": "application/json",
        "X-Gateway-Id": gateway_id,
        "X-NetVisor-Key-Version": str(key_version),
        "X-NetVisor-Timestamp": timestamp,
        "X-NetVisor-Nonce": nonce,
        "X-NetVisor-Signature": signature,
    }


def test_gateway_register_bootstrap_returns_initial_credential(monkeypatch):
    monkeypatch.setattr(settings, "GATEWAY_API_KEY", "bootstrap-key")
    monkeypatch.setattr(settings, "BACKEND_TLS_PINS_JSON", "[]")
    monkeypatch.setattr(settings, "GATEWAY_MASTER_KEY", "unit-test-gateway-master-key")

    conn = _Connection()
    upserts = []

    def _upsert(db_conn, *, gateway_id, organization_id, hostname, capture_mode):
        db_conn.gateway_orgs[gateway_id] = organization_id
        upserts.append((gateway_id, organization_id, hostname, capture_mode))

    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(gateway_api.gateway_service, "upsert_gateway", _upsert)

    request = _Request(method="POST", path="/api/v1/gateway/register", headers={"X-Gateway-Key": "bootstrap-key"})
    assert _run(gateway_api.validate_gateway_bootstrap_key(request)) is True

    payload = _run(
        gateway_api.register_gateway(
            {"gateway_id": "GW-1", "hostname": "gw-host", "capture_mode": "mirror"},
            _rate_limited=True,
            authorized=True,
        )
    )

    assert payload["organization_id"] == "default-org-id"
    assert payload["gateway_auth"]["mode"] == "bootstrap"
    assert payload["message"] == "Gateway registered and enrolled successfully."
    assert payload["gateway_credentials"]["gateway_id"] == "GW-1"
    assert upserts == [("GW-1", "default-org-id", "gw-host", "mirror")]
    assert ("GW-1", 1) in conn.credentials


def test_gateway_register_reenroll_rotates_existing_credential(monkeypatch):
    monkeypatch.setattr(settings, "GATEWAY_API_KEY", "bootstrap-key")
    monkeypatch.setattr(settings, "BACKEND_TLS_PINS_JSON", "[]")
    monkeypatch.setattr(settings, "GATEWAY_MASTER_KEY", "unit-test-gateway-master-key")

    existing_secret, existing_row = _seed_credential(monkeypatch, "GW-1")
    conn = _Connection(credentials={("GW-1", 1): existing_row})
    upserts = []

    def _upsert(db_conn, *, gateway_id, organization_id, hostname, capture_mode):
        db_conn.gateway_orgs[gateway_id] = organization_id
        upserts.append((gateway_id, organization_id, hostname, capture_mode))

    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(gateway_api.gateway_service, "upsert_gateway", _upsert)

    request = _Request(method="POST", path="/api/v1/gateway/register", headers={"X-Gateway-Key": "bootstrap-key"})
    assert _run(gateway_api.validate_gateway_bootstrap_key(request)) is True

    payload = _run(
        gateway_api.register_gateway(
            {"gateway_id": "GW-1", "hostname": "gw-host", "capture_mode": "mirror", "reenroll": True},
            _rate_limited=True,
            authorized=True,
        )
    )

    assert payload["gateway_auth"]["mode"] == "bootstrap"
    assert payload["message"] == "Gateway re-enrolled successfully. Previous credential is now invalid."
    assert payload["gateway_credentials"]["gateway_id"] == "GW-1"
    assert payload["gateway_credentials"]["key_version"] == 2
    assert conn.credentials[("GW-1", 1)]["status"] == "rotated"
    assert conn.credentials[("GW-1", 2)]["status"] == "active"
    assert upserts == [("GW-1", "default-org-id", "gw-host", "mirror")]


def test_gateway_validate_request_rejects_bootstrap_key_only(monkeypatch):
    monkeypatch.setattr(settings, "GATEWAY_MASTER_KEY", "unit-test-gateway-master-key")
    conn = _Connection()
    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)

    request = _Request(
        method="POST",
        path="/api/v1/gateway/heartbeat",
        headers={"X-Gateway-Key": "bootstrap-key"},
        body=b'{"gateway_id":"GW-1"}',
    )

    with pytest.raises(HTTPException, match="Signed gateway authentication is required"):
        _run(gateway_api.validate_gateway_request(request))


def test_gateway_heartbeat_accepts_signed_auth(monkeypatch):
    monkeypatch.setattr(settings, "BACKEND_TLS_PINS_JSON", "[]")
    monkeypatch.setattr(settings, "AGENT_MAX_CLOCK_SKEW_SECONDS", 60)
    monkeypatch.setattr(settings, "AGENT_NONCE_TTL_SECONDS", 300)
    secret, row = _seed_credential(monkeypatch, "GW-1")
    conn = _Connection(credentials={("GW-1", 1): row}, gateway_orgs={"GW-1": "default-org-id"})
    upserts = []

    def _upsert(db_conn, *, gateway_id, organization_id, hostname, capture_mode):
        upserts.append((gateway_id, organization_id, hostname, capture_mode))

    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(gateway_api.gateway_service, "upsert_gateway", _upsert)

    body = json.dumps(
        {"gateway_id": "GW-1", "hostname": "gw-host", "capture_mode": "promiscuous"},
        separators=(",", ":"),
    ).encode("utf-8")
    auth_context = _run(
        gateway_api.validate_gateway_request(
            _Request(
                method="POST",
                path="/api/v1/gateway/heartbeat",
                headers=_signed_headers(
                    secret=secret,
                    gateway_id="GW-1",
                    key_version=1,
                    path="/api/v1/gateway/heartbeat",
                    body=body,
                ),
                body=body,
            )
        )
    )

    payload = _run(
        gateway_api.gateway_heartbeat(
            json.loads(body.decode("utf-8")),
            _rate_limited=True,
            auth_context=auth_context,
        )
    )

    assert payload["gateway_auth"]["mode"] == "signed"
    assert payload["message"] == "Gateway heartbeat recorded."
    assert payload["organization_id"] == "default-org-id"
    assert upserts == [("GW-1", "default-org-id", "gw-host", "promiscuous")]


def test_gateway_flow_batch_accepts_signed_auth_and_normalizes_payload(monkeypatch):
    monkeypatch.setattr(settings, "BACKEND_TLS_PINS_JSON", "[]")
    monkeypatch.setattr(settings, "AGENT_MAX_CLOCK_SKEW_SECONDS", 60)
    monkeypatch.setattr(settings, "AGENT_NONCE_TTL_SECONDS", 300)
    secret, row = _seed_credential(monkeypatch, "GW-1")
    conn = _Connection(credentials={("GW-1", 1): row}, gateway_orgs={"GW-1": "default-org-id"})
    buffered = []

    async def _buffer_flows(flows):
        buffered.extend(flows)
        return True

    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(gateway_api.flow_service, "buffer_flows", _buffer_flows)

    flow = FlowBase(
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=443,
        protocol="tcp",
        domain="example.com",
        sni="example.com",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:AA:BB",
        packet_count=10,
        byte_count=1200,
        duration=1.25,
        agent_id="GW-1",
        organization_id="default-org-id",
        start_time="2026-04-16T00:00:00Z",
        last_seen="2026-04-16T00:00:01Z",
        average_packet_size=120.0,
        source_type="agent",
        metadata_only=False,
    )
    body = json.dumps([flow.model_dump(mode="json")], separators=(",", ":")).encode("utf-8")
    auth_context = _run(
        gateway_api.validate_gateway_request(
            _Request(
                method="POST",
                path="/api/v1/gateway/flows/batch",
                headers=_signed_headers(
                    secret=secret,
                    gateway_id="GW-1",
                    key_version=1,
                    path="/api/v1/gateway/flows/batch",
                    body=body,
                ),
                body=body,
            )
        )
    )

    payload = _run(
        gateway_api.ingest_gateway_batch(
            [flow],
            _rate_limited=True,
            auth_context=auth_context,
        )
    )

    assert payload["message"] == "Queued 1/1 gateway flows"
    assert len(buffered) == 1
    assert buffered[0].agent_id == "GW-1"
    assert buffered[0].organization_id == "default-org-id"
    assert buffered[0].source_type == "gateway"
    assert buffered[0].metadata_only is True


def test_gateway_flow_batch_returns_429_when_backpressure_is_active(monkeypatch):
    monkeypatch.setattr(settings, "BACKEND_TLS_PINS_JSON", "[]")
    monkeypatch.setattr(settings, "AGENT_MAX_CLOCK_SKEW_SECONDS", 60)
    monkeypatch.setattr(settings, "AGENT_NONCE_TTL_SECONDS", 300)
    secret, row = _seed_credential(monkeypatch, "GW-1")
    conn = _Connection(credentials={("GW-1", 1): row}, gateway_orgs={"GW-1": "default-org-id"})

    async def _buffer_flows(flows):
        raise FlowQueueBackpressureError("queue overloaded")

    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(gateway_api.flow_service, "buffer_flows", _buffer_flows)

    flow = FlowBase(
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=443,
        protocol="tcp",
        domain="example.com",
        sni="example.com",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:AA:BB",
        packet_count=10,
        byte_count=1200,
        duration=1.25,
        agent_id="GW-1",
        organization_id="default-org-id",
        start_time="2026-04-16T00:00:00Z",
        last_seen="2026-04-16T00:00:01Z",
        average_packet_size=120.0,
        source_type="agent",
        metadata_only=False,
    )
    body = json.dumps([flow.model_dump(mode="json")], separators=(",", ":")).encode("utf-8")
    auth_context = _run(
        gateway_api.validate_gateway_request(
            _Request(
                method="POST",
                path="/api/v1/gateway/flows/batch",
                headers=_signed_headers(
                    secret=secret,
                    gateway_id="GW-1",
                    key_version=1,
                    path="/api/v1/gateway/flows/batch",
                    body=body,
                ),
                body=body,
            )
        )
    )

    with pytest.raises(HTTPException) as exc_info:
        _run(
            gateway_api.ingest_gateway_batch(
                [flow],
                _rate_limited=True,
                auth_context=auth_context,
            )
        )

    assert exc_info.value.status_code == 429


def test_rotate_gateway_credential_rotates_versions(monkeypatch):
    monkeypatch.setattr(settings, "BACKEND_TLS_PINS_JSON", "[]")
    monkeypatch.setattr(settings, "AGENT_MAX_CLOCK_SKEW_SECONDS", 60)
    monkeypatch.setattr(settings, "AGENT_NONCE_TTL_SECONDS", 300)
    secret, row = _seed_credential(monkeypatch, "GW-1")
    conn = _Connection(credentials={("GW-1", 1): row}, gateway_orgs={"GW-1": "default-org-id"})

    monkeypatch.setattr(gateway_api, "get_db_connection", lambda: conn)

    body = json.dumps({"gateway_id": "GW-1"}, separators=(",", ":")).encode("utf-8")
    auth_context = _run(
        gateway_api.validate_gateway_request(
            _Request(
                method="POST",
                path="/api/v1/gateway/rotate-credential",
                headers=_signed_headers(
                    secret=secret,
                    gateway_id="GW-1",
                    key_version=1,
                    path="/api/v1/gateway/rotate-credential",
                    body=body,
                ),
                body=body,
            )
        )
    )

    payload = _run(
        gateway_api.rotate_gateway_credential(
            {"gateway_id": "GW-1"},
            _rate_limited=True,
            auth_context=auth_context,
        )
    )

    assert payload["gateway_credentials"]["key_version"] == 2
    assert conn.credentials[("GW-1", 1)]["status"] == "rotated"
    assert conn.credentials[("GW-1", 2)]["status"] == "active"
