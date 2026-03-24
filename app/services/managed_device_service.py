from __future__ import annotations

from typing import Optional, Set
import logging

logger = logging.getLogger("netvisor.managed_devices")


class ManagedDeviceService:
    def __init__(self) -> None:
        self._schema_ready = False

    def ensure_table(self, db_conn) -> None:
        if self._schema_ready:
            return

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS managed_devices (
                    agent_id VARCHAR(100) PRIMARY KEY,
                    organization_id CHAR(36),
                    device_ip VARCHAR(50) NOT NULL,
                    device_mac VARCHAR(50) DEFAULT '-',
                    hostname VARCHAR(100) DEFAULT 'Unknown',
                    os_family VARCHAR(50) DEFAULT 'Unknown',
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_managed_ip_org (device_ip, organization_id)
                )
                """
            )
            db_conn.commit()
        finally:
            cursor.close()

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
