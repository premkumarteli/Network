from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import hashlib
import logging
import uuid

from ..core.config import settings

logger = logging.getLogger("netvisor.agent_enrollment")


class AgentEnrollmentService:
    def __init__(self) -> None:
        self._schema_ready = False

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_enrollment_requests (
                    request_id CHAR(36) PRIMARY KEY,
                    agent_id VARCHAR(100) NOT NULL,
                    organization_id CHAR(36),
                    hostname VARCHAR(100) DEFAULT 'Unknown',
                    device_ip VARCHAR(50) DEFAULT '-',
                    device_mac VARCHAR(50) DEFAULT '-',
                    os_family VARCHAR(50) DEFAULT 'Unknown',
                    agent_version VARCHAR(50) DEFAULT 'Unknown',
                    bootstrap_method VARCHAR(32) DEFAULT 'bootstrap',
                    source_ip VARCHAR(50),
                    machine_fingerprint CHAR(64),
                    status VARCHAR(20) NOT NULL DEFAULT 'pending_review',
                    attempt_count INT NOT NULL DEFAULT 0,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NULL,
                    reviewed_by VARCHAR(100),
                    reviewed_at DATETIME NULL,
                    review_reason TEXT,
                    credential_issued_at DATETIME NULL,
                    UNIQUE KEY uq_agent_enrollment_agent (agent_id),
                    INDEX idx_agent_enrollment_status_last_seen (status, last_seen),
                    INDEX idx_agent_enrollment_org_last_seen (organization_id, last_seen),
                    INDEX idx_agent_enrollment_fingerprint (machine_fingerprint),
                    INDEX idx_agent_enrollment_expires_at (expires_at),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
                )
                """
            )
            db_conn.commit()
            self._schema_ready = True
        finally:
            cursor.close()

    def _format_timestamp(self, value) -> str | None:
        if not value:
            return None
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value)

    def _normalize_text(self, value, default: str = "Unknown") -> str:
        normalized = str(value or "").strip()
        return normalized or default

    def _normalize_ip(self, value, default: str = "-") -> str:
        normalized = str(value or "").strip()
        return normalized or default

    def _machine_fingerprint(
        self,
        *,
        agent_id: str,
        hostname: str,
        device_ip: str,
        device_mac: str,
        os_family: str,
        agent_version: str,
        source_ip: str,
    ) -> str:
        material = "|".join(
            [
                agent_id.strip().lower(),
                hostname.strip().lower(),
                device_ip.strip().lower(),
                device_mac.strip().lower(),
                os_family.strip().lower(),
                agent_version.strip().lower(),
                source_ip.strip().lower(),
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _row_to_request(self, row: dict | None) -> dict | None:
        if not row:
            return None
        return {
            "request_id": row.get("request_id"),
            "agent_id": row.get("agent_id"),
            "organization_id": row.get("organization_id"),
            "hostname": row.get("hostname") or "Unknown",
            "device_ip": row.get("device_ip") or "-",
            "device_mac": row.get("device_mac") or "-",
            "os_family": row.get("os_family") or "Unknown",
            "agent_version": row.get("agent_version") or "Unknown",
            "bootstrap_method": row.get("bootstrap_method") or "bootstrap",
            "source_ip": row.get("source_ip"),
            "machine_fingerprint": row.get("machine_fingerprint"),
            "status": row.get("status") or "pending_review",
            "attempt_count": int(row.get("attempt_count") or 0),
            "first_seen": self._format_timestamp(row.get("first_seen")),
            "last_seen": self._format_timestamp(row.get("last_seen")),
            "expires_at": self._format_timestamp(row.get("expires_at")),
            "reviewed_by": row.get("reviewed_by"),
            "reviewed_at": self._format_timestamp(row.get("reviewed_at")),
            "review_reason": row.get("review_reason"),
            "credential_issued_at": self._format_timestamp(row.get("credential_issued_at")),
        }

    def _fetch_request_by_agent(self, db_conn, *, agent_id: str) -> dict | None:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT *
                FROM agent_enrollment_requests
                WHERE agent_id = %s
                LIMIT 1
                """,
                (agent_id,),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _fetch_request_by_id(self, db_conn, *, request_id: str) -> dict | None:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT *
                FROM agent_enrollment_requests
                WHERE request_id = %s
                LIMIT 1
                """,
                (request_id,),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _expire_pending_requests(self, db_conn, *, organization_id: Optional[str] = None) -> int:
        cursor = db_conn.cursor()
        try:
            query = """
                UPDATE agent_enrollment_requests
                SET status = 'expired',
                    reviewed_by = COALESCE(reviewed_by, 'system'),
                    reviewed_at = COALESCE(reviewed_at, UTC_TIMESTAMP()),
                    review_reason = COALESCE(review_reason, 'Enrollment request expired after pending TTL.')
                WHERE status = 'pending_review'
                  AND expires_at IS NOT NULL
                  AND expires_at < UTC_TIMESTAMP()
            """
            params: list = []
            if organization_id:
                query += " AND (organization_id = %s OR organization_id IS NULL)"
                params.append(organization_id)
            cursor.execute(query, tuple(params))
            if cursor.rowcount:
                db_conn.commit()
            return int(cursor.rowcount or 0)
        finally:
            cursor.close()

    def record_request(
        self,
        db_conn,
        *,
        agent_id: str,
        organization_id: Optional[str],
        hostname: Optional[str],
        device_ip: Optional[str],
        device_mac: Optional[str],
        os_family: Optional[str],
        agent_version: Optional[str],
        bootstrap_method: str,
        source_ip: Optional[str],
    ) -> dict:
        self.ensure_schema(db_conn)
        self._expire_pending_requests(db_conn, organization_id=organization_id)

        normalized_agent_id = self._normalize_text(agent_id, default="")
        if not normalized_agent_id:
            raise ValueError("agent_id is required")

        hostname_value = self._normalize_text(hostname)
        device_ip_value = self._normalize_ip(device_ip)
        device_mac_value = self._normalize_ip(device_mac)
        os_family_value = self._normalize_text(os_family)
        agent_version_value = self._normalize_text(agent_version)
        bootstrap_method_value = self._normalize_text(bootstrap_method, default="bootstrap")
        source_ip_value = self._normalize_ip(source_ip, default="")
        fingerprint = self._machine_fingerprint(
            agent_id=normalized_agent_id,
            hostname=hostname_value,
            device_ip=device_ip_value,
            device_mac=device_mac_value,
            os_family=os_family_value,
            agent_version=agent_version_value,
            source_ip=source_ip_value,
        )
        ttl_seconds = max(int(settings.AGENT_ENROLLMENT_PENDING_TTL_SECONDS), 1)

        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT *
                FROM agent_enrollment_requests
                WHERE agent_id = %s
                LIMIT 1
                """,
                (normalized_agent_id,),
            )
            existing = cursor.fetchone()
            previous_status = str(existing.get("status") or "") if existing else None
            status_changed = False

            if existing:
                new_status = "approved" if previous_status == "approved" else "pending_review"
                if new_status != previous_status:
                    status_changed = True
                cursor.execute(
                    """
                    UPDATE agent_enrollment_requests
                    SET organization_id = %s,
                        hostname = %s,
                        device_ip = %s,
                        device_mac = %s,
                        os_family = %s,
                        agent_version = %s,
                        bootstrap_method = %s,
                        source_ip = %s,
                        machine_fingerprint = %s,
                        status = %s,
                        attempt_count = attempt_count + 1,
                        last_seen = UTC_TIMESTAMP(),
                        expires_at = CASE
                            WHEN %s = 'approved' THEN expires_at
                            ELSE DATE_ADD(UTC_TIMESTAMP(), INTERVAL %s SECOND)
                        END,
                        reviewed_by = CASE
                            WHEN %s = 'approved' THEN reviewed_by
                            ELSE NULL
                        END,
                        reviewed_at = CASE
                            WHEN %s = 'approved' THEN reviewed_at
                            ELSE NULL
                        END,
                        review_reason = CASE
                            WHEN %s = 'approved' THEN review_reason
                            ELSE NULL
                        END
                    WHERE agent_id = %s
                    """,
                    (
                        organization_id,
                        hostname_value,
                        device_ip_value,
                        device_mac_value,
                        os_family_value,
                        agent_version_value,
                        bootstrap_method_value,
                        source_ip_value or None,
                        fingerprint,
                        new_status,
                        new_status,
                        ttl_seconds,
                        new_status,
                        new_status,
                        new_status,
                        normalized_agent_id,
                    ),
                )
            else:
                request_id = str(uuid.uuid4())
                status_changed = True
                cursor.execute(
                    """
                    INSERT INTO agent_enrollment_requests (
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
                        status,
                        attempt_count,
                        first_seen,
                        last_seen,
                        expires_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        'pending_review', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP(),
                        DATE_ADD(UTC_TIMESTAMP(), INTERVAL %s SECOND)
                    )
                    """,
                    (
                        request_id,
                        normalized_agent_id,
                        organization_id,
                        hostname_value,
                        device_ip_value,
                        device_mac_value,
                        os_family_value,
                        agent_version_value,
                        bootstrap_method_value,
                        source_ip_value or None,
                        fingerprint,
                        ttl_seconds,
                    ),
                )

            db_conn.commit()
            current = self._fetch_request_by_agent(db_conn, agent_id=normalized_agent_id)
            return {
                "request": self._row_to_request(current),
                "status_changed": status_changed,
                "previous_status": previous_status,
            }
        finally:
            cursor.close()

    def list_requests(
        self,
        db_conn,
        *,
        organization_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        self._expire_pending_requests(db_conn, organization_id=organization_id)
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            query = """
                SELECT *
                FROM agent_enrollment_requests
            """
            where_clauses: list[str] = []
            if organization_id and not settings.SINGLE_ORG_MODE:
                where_clauses.append("(organization_id = %s OR organization_id IS NULL)")
                params.append(organization_id)
            if status:
                where_clauses.append("status = %s")
                params.append(status)
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
            query += " ORDER BY last_seen DESC"
            cursor.execute(query, tuple(params))
            return [self._row_to_request(row) for row in cursor.fetchall()]
        finally:
            cursor.close()

    def approve_request(
        self,
        db_conn,
        *,
        request_id: str,
        reviewed_by: str,
        review_reason: str,
    ) -> dict:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                UPDATE agent_enrollment_requests
                SET status = 'approved',
                    reviewed_by = %s,
                    reviewed_at = UTC_TIMESTAMP(),
                    review_reason = %s,
                    expires_at = NULL
                WHERE request_id = %s
                """,
                (reviewed_by or "system", review_reason, request_id),
            )
            if not cursor.rowcount:
                raise LookupError("Enrollment request not found")
            db_conn.commit()
            return self.get_request_by_id(db_conn, request_id=request_id)
        finally:
            cursor.close()

    def reject_request(
        self,
        db_conn,
        *,
        request_id: str,
        reviewed_by: str,
        review_reason: str,
    ) -> dict:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                UPDATE agent_enrollment_requests
                SET status = 'rejected',
                    reviewed_by = %s,
                    reviewed_at = UTC_TIMESTAMP(),
                    review_reason = %s,
                    expires_at = NULL
                WHERE request_id = %s
                """,
                (reviewed_by or "system", review_reason, request_id),
            )
            if not cursor.rowcount:
                raise LookupError("Enrollment request not found")
            db_conn.commit()
            return self.get_request_by_id(db_conn, request_id=request_id)
        finally:
            cursor.close()

    def revoke_request(
        self,
        db_conn,
        *,
        agent_id: str,
        reviewed_by: str,
        review_reason: str,
    ) -> dict:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                UPDATE agent_enrollment_requests
                SET status = 'revoked',
                    reviewed_by = %s,
                    reviewed_at = UTC_TIMESTAMP(),
                    review_reason = %s,
                    expires_at = NULL
                WHERE agent_id = %s
                """,
                (reviewed_by or "system", review_reason, agent_id),
            )
            if not cursor.rowcount:
                raise LookupError("Enrollment request not found")
            db_conn.commit()
            return self.get_request_by_agent_id(db_conn, agent_id=agent_id)
        finally:
            cursor.close()

    def mark_credential_issued(self, db_conn, *, agent_id: str, issued_at: Optional[str] = None) -> None:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor()
        try:
            if issued_at:
                cursor.execute(
                    """
                    UPDATE agent_enrollment_requests
                    SET credential_issued_at = %s,
                        status = 'approved'
                    WHERE agent_id = %s
                    """,
                    (issued_at, agent_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE agent_enrollment_requests
                    SET credential_issued_at = UTC_TIMESTAMP(),
                        status = 'approved'
                    WHERE agent_id = %s
                    """,
                    (agent_id,),
                )
            db_conn.commit()
        finally:
            cursor.close()

    def get_request_by_id(self, db_conn, *, request_id: str) -> dict | None:
        self.ensure_schema(db_conn)
        return self._row_to_request(self._fetch_request_by_id(db_conn, request_id=request_id))

    def get_request_by_agent_id(self, db_conn, *, agent_id: str) -> dict | None:
        self.ensure_schema(db_conn)
        return self._row_to_request(self._fetch_request_by_agent(db_conn, agent_id=agent_id))


agent_enrollment_service = AgentEnrollmentService()
