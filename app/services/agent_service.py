from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
import logging
import json

from ..core.config import settings
from .device_service import device_service
from .managed_device_service import managed_device_service

logger = logging.getLogger("netvisor.agent_monitoring")


class AgentService:
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

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return

        managed_device_service.ensure_table(db_conn)
        cursor = db_conn.cursor()
        try:
            if not self._column_exists(cursor, "agents", "hostname"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN hostname VARCHAR(100) NULL AFTER name
                    """
                )

            if not self._column_exists(cursor, "agents", "ip_address"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN ip_address VARCHAR(50) NULL AFTER organization_id
                    """
                )

            if not self._column_exists(cursor, "agents", "os_family"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN os_family VARCHAR(50) NULL AFTER ip_address
                    """
                )

            if not self._column_exists(cursor, "agents", "version"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN version VARCHAR(50) NULL AFTER os_family
                    """
                )

            if not self._column_exists(cursor, "agents", "inspection_enabled"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN inspection_enabled BOOLEAN DEFAULT FALSE AFTER version
                    """
                )

            if not self._column_exists(cursor, "agents", "inspection_status"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN inspection_status VARCHAR(32) DEFAULT 'disabled' AFTER inspection_enabled
                    """
                )

            if not self._column_exists(cursor, "agents", "inspection_proxy_running"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN inspection_proxy_running BOOLEAN DEFAULT FALSE AFTER inspection_status
                    """
                )

            if not self._column_exists(cursor, "agents", "inspection_ca_installed"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN inspection_ca_installed BOOLEAN DEFAULT FALSE AFTER inspection_proxy_running
                    """
                )

            if not self._column_exists(cursor, "agents", "inspection_browsers_json"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN inspection_browsers_json TEXT NULL AFTER inspection_ca_installed
                    """
                )

            if not self._column_exists(cursor, "agents", "inspection_last_error"):
                cursor.execute(
                    """
                    ALTER TABLE agents
                    ADD COLUMN inspection_last_error TEXT NULL AFTER inspection_browsers_json
                    """
                )

            if not self._index_exists(cursor, "agents", "idx_agents_org_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_agents_org_last_seen
                    ON agents (organization_id, last_seen)
                    """
                )

            if not self._index_exists(cursor, "devices", "idx_devices_agent_org_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_devices_agent_org_last_seen
                    ON devices (agent_id, organization_id, last_seen)
                    """
                )

            cursor.execute(
                """
                UPDATE agents a
                LEFT JOIN managed_devices md ON md.agent_id = a.id
                SET
                    a.hostname = COALESCE(NULLIF(a.hostname, ''), NULLIF(a.name, ''), NULLIF(md.hostname, ''), 'Unknown'),
                    a.ip_address = COALESCE(NULLIF(a.ip_address, ''), NULLIF(md.device_ip, ''), a.ip_address),
                    a.os_family = COALESCE(NULLIF(a.os_family, ''), NULLIF(md.os_family, ''), a.os_family)
                """
            )
            db_conn.commit()
            self._schema_ready = True
        finally:
            cursor.close()

    def upsert_agent(
        self,
        db_conn,
        *,
        agent_id: str,
        organization_id: Optional[str],
        api_key: Optional[str] = None,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        os_family: Optional[str] = None,
        version: Optional[str] = None,
        inspection_state: Optional[dict] = None,
    ) -> None:
        if not agent_id:
            return

        self.ensure_schema(db_conn)

        cursor = db_conn.cursor()
        try:
            normalized_hostname = (hostname or "Unknown").strip() or "Unknown"
            normalized_ip = (ip_address or "").strip() or None
            normalized_os = (os_family or "").strip() or None
            normalized_version = (version or "").strip() or None
            inspection_state = inspection_state or {}
            inspection_enabled = bool(inspection_state.get("inspection_enabled"))
            inspection_status = str(inspection_state.get("status") or "disabled")[:32]
            inspection_proxy_running = bool(inspection_state.get("proxy_running"))
            inspection_ca_installed = bool(inspection_state.get("ca_installed"))
            inspection_browsers_json = json.dumps(inspection_state.get("browser_support") or [])
            inspection_last_error = inspection_state.get("last_error")

            cursor.execute(
                """
                INSERT INTO agents (
                    id, name, hostname, api_key, organization_id, ip_address, os_family, version,
                    inspection_enabled, inspection_status, inspection_proxy_running, inspection_ca_installed,
                    inspection_browsers_json, inspection_last_error, last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name),
                    hostname = VALUES(hostname),
                    api_key = VALUES(api_key),
                    organization_id = VALUES(organization_id),
                    ip_address = COALESCE(NULLIF(VALUES(ip_address), ''), ip_address),
                    os_family = COALESCE(NULLIF(VALUES(os_family), ''), os_family),
                    version = COALESCE(NULLIF(VALUES(version), ''), version),
                    inspection_enabled = VALUES(inspection_enabled),
                    inspection_status = VALUES(inspection_status),
                    inspection_proxy_running = VALUES(inspection_proxy_running),
                    inspection_ca_installed = VALUES(inspection_ca_installed),
                    inspection_browsers_json = VALUES(inspection_browsers_json),
                    inspection_last_error = VALUES(inspection_last_error),
                    last_seen = UTC_TIMESTAMP()
                """,
                (
                    agent_id,
                    normalized_hostname,
                    normalized_hostname,
                    api_key,
                    organization_id,
                    normalized_ip,
                    normalized_os,
                    normalized_version,
                    inspection_enabled,
                    inspection_status,
                    inspection_proxy_running,
                    inspection_ca_installed,
                    inspection_browsers_json,
                    inspection_last_error,
                ),
            )
            db_conn.commit()
        finally:
            cursor.close()

    def _format_timestamp(self, value) -> str:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value or "")

    def _heartbeat_age_seconds(self, last_seen) -> Optional[int]:
        if not last_seen:
            return None
        if isinstance(last_seen, str):
            try:
                last_seen = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        elif getattr(last_seen, "tzinfo", None) is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        else:
            last_seen = last_seen.astimezone(timezone.utc)

        delta = datetime.now(timezone.utc) - last_seen
        return max(int(delta.total_seconds()), 0)

    def _build_agent_entry(
        self,
        row: dict,
        *,
        device_count: int,
        online_window_seconds: int = 20,
    ) -> dict:
        hostname = (
            row.get("hostname")
            or row.get("name")
            or row.get("managed_hostname")
            or "Unknown"
        )
        ip_address = row.get("ip_address") or row.get("managed_ip") or "-"
        last_seen = row.get("last_seen")
        heartbeat_age_seconds = self._heartbeat_age_seconds(last_seen)
        status = (
            "Online"
            if heartbeat_age_seconds is not None and heartbeat_age_seconds <= online_window_seconds
            else "Offline"
        )

        return {
            "agent_id": row.get("agent_id") or row.get("id") or "",
            "hostname": hostname,
            "ip_address": ip_address,
            "status": status,
            "last_seen": self._format_timestamp(last_seen),
            "heartbeat_age_seconds": heartbeat_age_seconds,
            "device_count": int(device_count or 0),
            "os_family": row.get("os_family") or row.get("managed_os_family") or "Unknown",
            "version": row.get("version") or "Unknown",
            "inspection_enabled": bool(row.get("inspection_enabled")),
            "inspection_status": row.get("inspection_status") or "disabled",
            "inspection_proxy_running": bool(row.get("inspection_proxy_running")),
            "inspection_ca_installed": bool(row.get("inspection_ca_installed")),
            "inspection_browsers": self._json_list(row.get("inspection_browsers_json")),
            "inspection_last_error": row.get("inspection_last_error"),
        }

    def _json_list(self, value) -> list[str]:
        if not value:
            return []
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return []
        return [str(item) for item in parsed if str(item).strip()]

    def _fetch_agents(self, db_conn, organization_id: Optional[str] = None) -> list[dict]:
        self.ensure_schema(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            query = """
                SELECT
                    a.id AS agent_id,
                    a.name,
                    a.hostname,
                    a.ip_address,
                    a.os_family,
                    a.version,
                    a.inspection_enabled,
                    a.inspection_status,
                    a.inspection_proxy_running,
                    a.inspection_ca_installed,
                    a.inspection_browsers_json,
                    a.inspection_last_error,
                    a.organization_id,
                    a.last_seen,
                    md.hostname AS managed_hostname,
                    md.device_ip AS managed_ip,
                    md.os_family AS managed_os_family
                FROM agents a
                LEFT JOIN managed_devices md ON md.agent_id = a.id
            """
            if organization_id and not settings.SINGLE_ORG_MODE:
                query += " WHERE a.organization_id = %s OR a.organization_id IS NULL"
                params.append(organization_id)
            query += " ORDER BY a.last_seen DESC"
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def _fetch_device_counts(self, db_conn, organization_id: Optional[str] = None) -> dict[str, int]:
        self.ensure_schema(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            managed_filter = ""
            observed_filter = "WHERE agent_id IS NOT NULL"
            if organization_id and not settings.SINGLE_ORG_MODE:
                managed_filter = " WHERE organization_id = %s OR organization_id IS NULL"
                observed_filter += " AND (organization_id = %s OR organization_id IS NULL)"
                params.extend([organization_id, organization_id])

            cursor.execute(
                f"""
                SELECT agent_id, COUNT(DISTINCT device_ip) AS device_count
                FROM (
                    SELECT agent_id, device_ip
                    FROM managed_devices
                    {managed_filter}
                    UNION ALL
                    SELECT agent_id, ip AS device_ip
                    FROM devices
                    {observed_filter}
                ) AS device_union
                WHERE agent_id IS NOT NULL
                GROUP BY agent_id
                """,
                tuple(params),
            )
            return {
                row["agent_id"]: int(row.get("device_count") or 0)
                for row in cursor.fetchall()
                if row.get("agent_id")
            }
        finally:
            cursor.close()

    def get_agents(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        online_window_seconds: int = 20,
    ) -> list[dict]:
        rows = self._fetch_agents(db_conn, organization_id=organization_id)
        counts = self._fetch_device_counts(db_conn, organization_id=organization_id)
        return [
            self._build_agent_entry(
                row,
                device_count=counts.get(row.get("agent_id"), 0),
                online_window_seconds=online_window_seconds,
            )
            for row in rows
        ]

    def _merge_device_rows(self, managed_rows: list[dict], observed_rows: list[dict]) -> list[dict]:
        merged: dict[str, dict] = {}

        for row in observed_rows + managed_rows:
            ip = row.get("ip")
            if not ip:
                continue
            existing = merged.get(ip)
            if existing is None or row.get("management_mode") == "managed":
                merged[ip] = row

        devices = list(merged.values())
        devices.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
        return devices

    def _fetch_agent_devices(
        self,
        db_conn,
        agent_id: str,
        organization_id: Optional[str] = None,
    ) -> list[dict]:
        self.ensure_schema(db_conn)

        managed_cursor = db_conn.cursor(dictionary=True)
        observed_cursor = db_conn.cursor(dictionary=True)
        try:
            managed_params: list = [agent_id]
            managed_query = """
                SELECT
                    md.device_ip AS ip,
                    md.hostname AS hostname,
                    md.device_mac AS mac,
                    'Managed Agent' AS vendor,
                    'Managed Endpoint' AS device_type,
                    md.os_family AS os_family,
                    TRUE AS is_online,
                    md.last_seen AS last_seen,
                    'managed' AS management_mode
                FROM managed_devices md
                WHERE md.agent_id = %s
            """
            if organization_id and not settings.SINGLE_ORG_MODE:
                managed_query += " AND (md.organization_id = %s OR md.organization_id IS NULL)"
                managed_params.append(organization_id)
            managed_cursor.execute(managed_query, tuple(managed_params))
            managed_rows = managed_cursor.fetchall()

            observed_params: list = [agent_id]
            observed_query = """
                SELECT
                    d.ip,
                    d.hostname,
                    d.mac,
                    d.vendor,
                    d.device_type,
                    d.os_family,
                    d.is_online,
                    d.last_seen,
                    'observed' AS management_mode
                FROM devices d
                WHERE d.agent_id = %s
            """
            if organization_id and not settings.SINGLE_ORG_MODE:
                observed_query += " AND (d.organization_id = %s OR d.organization_id IS NULL)"
                observed_params.append(organization_id)
            observed_query += " ORDER BY d.last_seen DESC"
            observed_cursor.execute(observed_query, tuple(observed_params))
            observed_rows = observed_cursor.fetchall()
        finally:
            managed_cursor.close()
            observed_cursor.close()

        devices = self._merge_device_rows(managed_rows, observed_rows)
        for device in devices:
            status = device_service.get_device_status(device.get("last_seen"))
            device["status"] = status
            device["is_online"] = status == "Online"
            device["last_seen"] = self._format_timestamp(device.get("last_seen"))
            device["hostname"] = device.get("hostname") or "Unknown"
            device["mac"] = device.get("mac") or "-"
            device["vendor"] = device.get("vendor") or "Unknown"
            device["device_type"] = device.get("device_type") or "Unknown"
            device["os_family"] = device.get("os_family") or "Unknown"
        return devices

    def get_agent_details(
        self,
        db_conn,
        agent_id: str,
        organization_id: Optional[str] = None,
        online_window_seconds: int = 20,
    ) -> Optional[dict]:
        agents = self.get_agents(
            db_conn,
            organization_id=organization_id,
            online_window_seconds=online_window_seconds,
        )
        agent = next((row for row in agents if row["agent_id"] == agent_id), None)
        if not agent:
            return None

        devices = self._fetch_agent_devices(db_conn, agent_id, organization_id=organization_id)
        agent["devices"] = devices
        agent["online_device_count"] = sum(1 for device in devices if device.get("status") == "Online")
        return agent


agent_service = AgentService()
