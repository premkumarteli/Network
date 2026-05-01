from __future__ import annotations

from typing import Optional, Set
import logging

from ..core.config import settings
from ..db.session import require_runtime_schema

logger = logging.getLogger("netvisor.managed_devices")


class ManagedDeviceService:
    def __init__(self) -> None:
        self._schema_ready = False

    def _column_exists(self, cursor, table_name: str, column_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s AND column_name = %s
            LIMIT 1
            """,
            (settings.DB_NAME, table_name, column_name),
        )
        return cursor.fetchone() is not None

    def _index_exists(self, cursor, table_name: str, index_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = %s AND table_name = %s AND index_name = %s
            LIMIT 1
            """,
            (settings.DB_NAME, table_name, index_name),
        )
        return cursor.fetchone() is not None

    def _primary_key_columns(self, cursor, table_name: str) -> list[str]:
        cursor.execute(
            """
            SELECT column_name
            FROM information_schema.key_column_usage
            WHERE table_schema = %s
              AND table_name = %s
              AND constraint_name = 'PRIMARY'
            ORDER BY ordinal_position
            """,
            (settings.DB_NAME, table_name),
        )
        return [row[0] for row in cursor.fetchall() if row and row[0]]

    def ensure_table(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def upsert_device(
        self,
        db_conn,
        *,
        agent_id: str,
        organization_id: Optional[str],
        device_ip: Optional[str],
        device_mac: Optional[str] = None,
        hostname: Optional[str] = None,
        os_family: Optional[str] = None,
    ) -> None:
        if not agent_id or not device_ip:
            return

        self.ensure_table(db_conn)

        cursor = db_conn.cursor()
        try:
            logger.debug(f"Upserting managed device agent_id={agent_id}, org_id={organization_id}, ip={device_ip}")
            cursor.execute(
                """
                INSERT INTO managed_devices (
                    agent_id, organization_id, device_ip, device_mac, hostname, os_family, first_seen, last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    agent_id = VALUES(agent_id),
                    organization_id = VALUES(organization_id),
                    device_ip = VALUES(device_ip),
                    device_mac = VALUES(device_mac),
                    hostname = VALUES(hostname),
                    os_family = VALUES(os_family),
                    last_seen = UTC_TIMESTAMP()
                """,
                (
                    agent_id,
                    organization_id,
                    device_ip,
                    device_mac or "-",
                    hostname or "Unknown",
                    os_family or "Unknown",
                ),
            )
            db_conn.commit()
        finally:
            cursor.close()

    def get_managed_ip_set(self, db_conn, organization_id: Optional[str] = None) -> Set[str]:
        self.ensure_table(db_conn)

        cursor = db_conn.cursor()
        try:
            query = "SELECT device_ip FROM managed_devices"
            params = []
            if organization_id:
                query += " WHERE organization_id = %s"
                params.append(organization_id)

            cursor.execute(query, tuple(params))
            return {row[0] for row in cursor.fetchall() if row and row[0]}
        finally:
            cursor.close()


managed_device_service = ManagedDeviceService()
