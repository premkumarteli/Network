from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.services.agent_enrollment_service import AgentEnrollmentService


class _EnrollmentCursor:
    def __init__(self, conn, dictionary: bool = False):
        self.conn = conn
        self.dictionary = dictionary
        self._result = None
        self.rowcount = 0

    def _store_row(self, row: dict) -> None:
        self.conn.rows_by_agent[row["agent_id"]] = row
        self.conn.rows_by_request[row["request_id"]] = row

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        params = tuple(params or ())
        self._result = None
        self.rowcount = 0

        if normalized.startswith("CREATE TABLE IF NOT EXISTS agent_enrollment_requests"):
            self.conn.schema_created = True
            return

        if normalized.startswith("UPDATE agent_enrollment_requests SET status = 'expired'"):
            expired = 0
            now = datetime.now(timezone.utc)
            org_id = params[0] if params else None
            for row in list(self.conn.rows_by_agent.values()):
                if row["status"] != "pending_review":
                    continue
                if row["expires_at"] is None or row["expires_at"] >= now:
                    continue
                if org_id and row["organization_id"] not in {org_id, None}:
                    continue
                row["status"] = "expired"
                row["reviewed_by"] = row["reviewed_by"] or "system"
                row["reviewed_at"] = row["reviewed_at"] or now
                row["review_reason"] = row["review_reason"] or "Enrollment request expired after pending TTL."
                expired += 1
            self.rowcount = expired
            return

        if normalized.startswith("SELECT * FROM agent_enrollment_requests WHERE agent_id = %s LIMIT 1"):
            row = self.conn.rows_by_agent.get(params[0])
            self._result = dict(row) if row else None
            return

        if normalized.startswith("SELECT * FROM agent_enrollment_requests WHERE request_id = %s LIMIT 1"):
            row = self.conn.rows_by_request.get(params[0])
            self._result = dict(row) if row else None
            return

        if normalized.startswith("SELECT * FROM agent_enrollment_requests"):
            rows = list(self.conn.rows_by_request.values())
            index = 0
            if "organization_id = %s OR organization_id IS NULL" in normalized:
                org_id = params[index]
                index += 1
                rows = [row for row in rows if row["organization_id"] in {org_id, None}]
            if "status = %s" in normalized:
                status = params[index]
                rows = [row for row in rows if row["status"] == status]
            rows.sort(key=lambda row: row["last_seen"], reverse=True)
            self._result = [dict(row) for row in rows]
            return

        if normalized.startswith("INSERT INTO agent_enrollment_requests"):
            (
                request_id,
                agent_id,
                organization_id,
                hostname,
                device_ip,
                device_mac,
                os_family,
                agent_version,
                bootstrap_method,
                source_ip,
                machine_fingerprint,
                ttl_seconds,
            ) = params
            now = datetime.now(timezone.utc)
            row = {
                "request_id": request_id,
                "agent_id": agent_id,
                "organization_id": organization_id,
                "hostname": hostname,
                "device_ip": device_ip,
                "device_mac": device_mac,
                "os_family": os_family,
                "agent_version": agent_version,
                "bootstrap_method": bootstrap_method,
                "source_ip": source_ip,
                "machine_fingerprint": machine_fingerprint,
                "status": "pending_review",
                "attempt_count": 1,
                "first_seen": now,
                "last_seen": now,
                "expires_at": now + timedelta(seconds=int(ttl_seconds)),
                "reviewed_by": None,
                "reviewed_at": None,
                "review_reason": None,
                "credential_issued_at": None,
            }
            self._store_row(row)
            self.rowcount = 1
            return

        if normalized.startswith("UPDATE agent_enrollment_requests SET organization_id = %s"):
            agent_id = params[-1]
            row = self.conn.rows_by_agent.get(agent_id)
            if not row:
                return
            (
                organization_id,
                hostname,
                device_ip,
                device_mac,
                os_family,
                agent_version,
                bootstrap_method,
                source_ip,
                machine_fingerprint,
                new_status,
                _status_repeat,
                ttl_seconds,
                _approved_status_1,
                _approved_status_2,
                _approved_status_3,
                _agent_id,
            ) = params
            now = datetime.now(timezone.utc)
            row.update(
                {
                    "organization_id": organization_id,
                    "hostname": hostname,
                    "device_ip": device_ip,
                    "device_mac": device_mac,
                    "os_family": os_family,
                    "agent_version": agent_version,
                    "bootstrap_method": bootstrap_method,
                    "source_ip": source_ip,
                    "machine_fingerprint": machine_fingerprint,
                    "status": new_status,
                    "attempt_count": int(row.get("attempt_count") or 0) + 1,
                    "last_seen": now,
                    "expires_at": row["expires_at"] if new_status == "approved" else now + timedelta(seconds=int(ttl_seconds)),
                }
            )
            if new_status != "approved":
                row["reviewed_by"] = None
                row["reviewed_at"] = None
                row["review_reason"] = None
            self.rowcount = 1
            return

        if normalized.startswith("UPDATE agent_enrollment_requests SET status = 'approved'"):
            request_id = params[2]
            row = self.conn.rows_by_request.get(request_id)
            if not row:
                return
            row["status"] = "approved"
            row["reviewed_by"] = params[0]
            row["reviewed_at"] = datetime.now(timezone.utc)
            row["review_reason"] = params[1]
            row["expires_at"] = None
            self.rowcount = 1
            return

        if normalized.startswith("UPDATE agent_enrollment_requests SET status = 'rejected'"):
            request_id = params[2]
            row = self.conn.rows_by_request.get(request_id)
            if not row:
                return
            row["status"] = "rejected"
            row["reviewed_by"] = params[0]
            row["reviewed_at"] = datetime.now(timezone.utc)
            row["review_reason"] = params[1]
            row["expires_at"] = None
            self.rowcount = 1
            return

        if normalized.startswith("UPDATE agent_enrollment_requests SET status = 'revoked'"):
            agent_id = params[2]
            row = self.conn.rows_by_agent.get(agent_id)
            if not row:
                return
            row["status"] = "revoked"
            row["reviewed_by"] = params[0]
            row["reviewed_at"] = datetime.now(timezone.utc)
            row["review_reason"] = params[1]
            row["expires_at"] = None
            self.rowcount = 1
            return

        if normalized.startswith("UPDATE agent_enrollment_requests SET credential_issued_at ="):
            if "UTC_TIMESTAMP()" in normalized:
                agent_id = params[0]
                issued_at = datetime.now(timezone.utc)
            else:
                issued_at = params[0]
                agent_id = params[1]
                if isinstance(issued_at, str):
                    issued_at = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
            row = self.conn.rows_by_agent.get(agent_id)
            if not row:
                return
            row["credential_issued_at"] = issued_at
            row["status"] = "approved"
            self.rowcount = 1
            return

        raise AssertionError(f"Unexpected query: {normalized}")

    def fetchone(self):
        if isinstance(self._result, list):
            return self._result[0] if self._result else None
        return self._result

    def fetchall(self):
        if isinstance(self._result, list):
            return self._result
        return [self._result] if self._result is not None else []

    def close(self):
        return None


class _EnrollmentConnection:
    def __init__(self):
        self.rows_by_agent: dict[str, dict] = {}
        self.rows_by_request: dict[str, dict] = {}
        self.schema_created = False
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, dictionary=False):
        return _EnrollmentCursor(self, dictionary=dictionary)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        return None


def _create_request(service: AgentEnrollmentService, conn: _EnrollmentConnection, *, agent_id: str, hostname: str):
    return service.record_request(
        conn,
        agent_id=agent_id,
        organization_id="org-1",
        hostname=hostname,
        device_ip="10.0.0.10",
        device_mac="aa:bb:cc:dd:ee:ff",
        os_family="Windows",
        agent_version="v3.0-hybrid",
        bootstrap_method="bootstrap",
        source_ip="10.0.0.1",
    )


def test_record_request_creates_pending_request_and_retries_increment_attempt_count(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_ENROLLMENT_PENDING_TTL_SECONDS", 120)
    service = AgentEnrollmentService()
    conn = _EnrollmentConnection()

    first = _create_request(service, conn, agent_id="AGENT-1", hostname="desk-1")
    second = _create_request(service, conn, agent_id="AGENT-1", hostname="desk-1-renamed")

    assert first["status_changed"] is True
    assert first["request"]["status"] == "pending_review"
    assert first["request"]["attempt_count"] == 1
    assert first["request"]["expires_at"] is not None

    assert second["status_changed"] is False
    assert second["request"]["request_id"] == first["request"]["request_id"]
    assert second["request"]["attempt_count"] == 2
    assert second["request"]["hostname"] == "desk-1-renamed"
    assert conn.commits >= 2


def test_record_request_keeps_approved_status_after_review(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_ENROLLMENT_PENDING_TTL_SECONDS", 120)
    service = AgentEnrollmentService()
    conn = _EnrollmentConnection()

    created = _create_request(service, conn, agent_id="AGENT-2", hostname="desk-2")
    approved = service.approve_request(
        conn,
        request_id=created["request"]["request_id"],
        reviewed_by="admin",
        review_reason="Approved after review",
    )
    replay = _create_request(service, conn, agent_id="AGENT-2", hostname="desk-2-new")

    assert approved["status"] == "approved"
    assert approved["reviewed_by"] == "admin"
    assert approved["review_reason"] == "Approved after review"
    assert replay["request"]["status"] == "approved"
    assert replay["status_changed"] is False
    assert replay["request"]["attempt_count"] == 2
    assert replay["request"]["reviewed_by"] == "admin"


def test_reject_and_revoke_requests_update_status(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_ENROLLMENT_PENDING_TTL_SECONDS", 120)
    service = AgentEnrollmentService()
    conn = _EnrollmentConnection()

    rejected_created = _create_request(service, conn, agent_id="AGENT-3", hostname="desk-3")
    revoked_created = _create_request(service, conn, agent_id="AGENT-4", hostname="desk-4")

    rejected = service.reject_request(
        conn,
        request_id=rejected_created["request"]["request_id"],
        reviewed_by="admin",
        review_reason="Unknown asset",
    )
    revoked = service.revoke_request(
        conn,
        agent_id="AGENT-4",
        reviewed_by="admin",
        review_reason="Asset removed",
    )

    assert rejected["status"] == "rejected"
    assert rejected["reviewed_by"] == "admin"
    assert rejected["review_reason"] == "Unknown asset"
    assert revoked["status"] == "revoked"
    assert revoked["reviewed_by"] == "admin"
    assert revoked["review_reason"] == "Asset removed"
