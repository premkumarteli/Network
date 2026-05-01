import json
from datetime import datetime, timezone

import pytest

from shared.security.agent_auth import sign_request
from app.core.config import settings
from app.services.agent_auth_service import AgentAuthenticationError, agent_auth_service


class FakeRequestUrl:
    def __init__(self, path: str, query: str = ""):
        self.path = path
        self.query = query


class FakeRequest:
    def __init__(self, *, method: str, path: str, headers: dict[str, str], query: str = ""):
        self.method = method
        self.url = FakeRequestUrl(path, query)
        self.headers = headers
        self.query_params = {}


class FakeCursor:
    def __init__(self, conn, dictionary=False):
        self.conn = conn
        self.dictionary = dictionary
        self._result = None

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        if normalized.startswith("DELETE FROM agent_request_nonces"):
            self._result = None
            return
        if normalized.startswith("INSERT INTO agent_request_nonces"):
            key = (params[0], int(params[1]), params[2])
            if key in self.conn.nonces:
                raise ValueError("duplicate nonce")
            self.conn.nonces.add(key)
            self._result = None
            return
        if "FROM agent_credentials" in normalized and "WHERE agent_id = %s AND key_version = %s" in normalized:
            self._result = self.conn.credentials.get((params[0], int(params[1])))
            return
        if (
            "FROM agent_credentials" in normalized
            and "WHERE agent_id = %s AND status = 'active'" in normalized
            and "ORDER BY key_version DESC LIMIT 1" in normalized
        ):
            agent_id = params[0]
            rows = [
                row
                for (stored_agent_id, _), row in self.conn.credentials.items()
                if stored_agent_id == agent_id and row.get("status") == "active"
            ]
            rows.sort(key=lambda row: int(row["key_version"]), reverse=True)
            self._result = rows[0] if rows else None
            return
        if normalized.startswith("SELECT COALESCE(MAX(key_version), 0) AS max_version FROM agent_credentials"):
            agent_id = params[0]
            versions = [version for (stored_agent_id, version) in self.conn.credentials if stored_agent_id == agent_id]
            self._result = {"max_version": max(versions) if versions else 0}
            return
        if normalized.startswith("INSERT INTO agent_credentials"):
            agent_id, key_version, secret_salt, secret_hash = params
            self.conn.credentials[(agent_id, int(key_version))] = {
                "agent_id": agent_id,
                "key_version": int(key_version),
                "secret_salt": secret_salt,
                "secret_hash": secret_hash,
                "status": "active",
                "issued_at": datetime.now(timezone.utc),
            }
            self._result = None
            return
        if normalized.startswith("UPDATE agent_credentials SET status = 'rotating'"):
            agent_id = params[0]
            for (stored_agent_id, _), row in self.conn.credentials.items():
                if stored_agent_id == agent_id and row.get("status") == "active":
                    row["status"] = "rotating"
            self._result = None
            return
        if normalized.startswith("UPDATE agent_credentials SET status = 'rotated'"):
            agent_id, key_version = params
            for (stored_agent_id, stored_version), row in self.conn.credentials.items():
                if (
                    stored_agent_id == agent_id
                    and stored_version < int(key_version)
                    and row.get("status") in {"active", "rotating"}
                ):
                    row["status"] = "rotated"
            self._result = None
            return
        if normalized.startswith("UPDATE agent_credentials SET last_used_at"):
            self.conn.last_used_updates.append((params[0], int(params[1])))
            self._result = None
            return
        raise AssertionError(f"Unexpected query: {normalized}")

    def fetchone(self):
        return self._result

    def close(self):
        return None


class FakeConnection:
    def __init__(self, credentials):
        self.credentials = credentials
        self.nonces = set()
        self.last_used_updates = []

    def cursor(self, dictionary=False):
        return FakeCursor(self, dictionary=dictionary)

    def commit(self):
        return None

    def rollback(self):
        return None


def test_signed_agent_request_is_accepted_and_nonce_reuse_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MASTER_KEY", "unit-test-agent-master-key")
    monkeypatch.setattr(settings, "AGENT_MAX_CLOCK_SKEW_SECONDS", 60)
    monkeypatch.setattr(settings, "AGENT_NONCE_TTL_SECONDS", 300)

    agent_id = "AGENT-1"
    key_version = 1
    secret_salt = "abc123salt"
    secret = agent_auth_service._derive_secret(
        agent_id=agent_id,
        key_version=key_version,
        secret_salt=secret_salt,
    )
    conn = FakeConnection(
        {
            (agent_id, key_version): {
                "agent_id": agent_id,
                "key_version": key_version,
                "secret_salt": secret_salt,
                "status": "active",
            }
        }
    )

    body = json.dumps({"agent_id": agent_id, "status": "online"}, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = "nonce-123"
    signature = sign_request(
        secret=secret,
        method="POST",
        path="/api/v1/collect/heartbeat",
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    request = FakeRequest(
        method="POST",
        path="/api/v1/collect/heartbeat",
        headers={
            "X-Agent-Id": agent_id,
            "X-NetVisor-Key-Version": str(key_version),
            "X-NetVisor-Timestamp": timestamp,
            "X-NetVisor-Nonce": nonce,
            "X-NetVisor-Signature": signature,
        },
    )

    context = agent_auth_service.authenticate_request(conn, request, body)

    assert context["auth_mode"] == "signed"
    assert context["agent_id"] == agent_id
    assert conn.last_used_updates == [(agent_id, key_version)]

    with pytest.raises(AgentAuthenticationError, match="Replay detected"):
        agent_auth_service.authenticate_request(conn, request, body)


def test_issue_initial_credential_only_issues_once(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MASTER_KEY", "unit-test-agent-master-key")

    agent_id = "AGENT-INIT"
    conn = FakeConnection({})

    credential = agent_auth_service.issue_initial_credential(conn, agent_id=agent_id)
    duplicate = agent_auth_service.issue_initial_credential(conn, agent_id=agent_id)

    assert credential is not None
    assert credential.agent_id == agent_id
    assert credential.key_version == 1
    assert duplicate is None


def test_rotate_credential_creates_new_version_and_rotates_previous(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MASTER_KEY", "unit-test-agent-master-key")

    agent_id = "AGENT-ROTATE"
    conn = FakeConnection({})
    initial = agent_auth_service.issue_initial_credential(conn, agent_id=agent_id)

    rotated = agent_auth_service.rotate_credential(conn, agent_id=agent_id)

    assert initial is not None
    assert rotated.agent_id == agent_id
    assert rotated.key_version == initial.key_version + 1
    assert conn.credentials[(agent_id, initial.key_version)]["status"] == "rotated"
    assert conn.credentials[(agent_id, rotated.key_version)]["status"] == "active"
