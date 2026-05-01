from __future__ import annotations

from hashlib import sha1
from typing import Optional

from ..db.session import require_runtime_schema

class SessionService:
    def __init__(self) -> None:
        self._schema_ready = False

    def ensure_table(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def build_session_id(
        self,
        *,
        organization_id: str | None,
        device_ip: str,
        application: str,
        domain: str | None,
        external_ip: str | None,
    ) -> str:
        parts = [
            organization_id or "-",
            device_ip,
            application or "Other",
            domain or "-",
            external_ip or "-",
        ]
        return sha1("|".join(parts).encode("utf-8")).hexdigest()

    def upsert_session(
        self,
        db_conn,
        *,
        organization_id: Optional[str],
        device_ip: str,
        device_mac: Optional[str],
        external_ip: Optional[str],
        application: str,
        domain: Optional[str],
        protocol: Optional[str],
        source_type: str,
        packet_count: int,
        byte_count: int,
        start_time,
        last_seen,
        duration: float,
    ) -> str:
        self.ensure_table(db_conn)
        session_id = self.build_session_id(
            organization_id=organization_id,
            device_ip=device_ip,
            application=application,
            domain=domain,
            external_ip=external_ip,
        )

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO sessions (
                    session_id,
                    organization_id,
                    device_ip,
                    device_mac,
                    external_ip,
                    application,
                    domain,
                    protocol,
                    source_type,
                    total_packets,
                    total_bytes,
                    first_seen,
                    last_seen,
                    duration
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    device_mac = COALESCE(NULLIF(VALUES(device_mac), ''), device_mac),
                    external_ip = COALESCE(NULLIF(VALUES(external_ip), ''), external_ip),
                    domain = COALESCE(NULLIF(VALUES(domain), ''), domain),
                    protocol = COALESCE(NULLIF(VALUES(protocol), ''), protocol),
                    source_type = VALUES(source_type),
                    total_packets = total_packets + VALUES(total_packets),
                    total_bytes = total_bytes + VALUES(total_bytes),
                    first_seen = LEAST(first_seen, VALUES(first_seen)),
                    last_seen = GREATEST(last_seen, VALUES(last_seen)),
                    duration = GREATEST(duration, VALUES(duration))
                """,
                (
                    session_id,
                    organization_id,
                    device_ip,
                    device_mac,
                    external_ip,
                    application or "Other",
                    domain,
                    protocol,
                    source_type,
                    max(int(packet_count or 0), 0),
                    max(int(byte_count or 0), 0),
                    start_time,
                    last_seen,
                    max(float(duration or 0), 0.0),
                ),
            )
            return session_id
        finally:
            cursor.close()


session_service = SessionService()
