from datetime import datetime, timezone
from typing import List, Optional
import logging

from ..core.config import settings
from ..utils.network import is_rfc1918_device_ip, normalize_ip, normalize_mac
from .managed_device_service import managed_device_service

logger = logging.getLogger("netvisor.devices")


class DeviceService:
    """
    Device service for MVP single-organization mode.
    Managed devices come from explicit agent registration.
    Unmanaged devices come from local L2 discovery only.
    Gateway-observed flows must never create devices directly.
    """

    ONLINE_WINDOW_SECONDS = 10
    IDLE_WINDOW_SECONDS = 60

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
            if not self._column_exists(cursor, "devices", "last_seen"):
                cursor.execute(
                    """
                    ALTER TABLE devices
                    ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                    """
                )

            if not self._column_exists(cursor, "devices", "first_seen"):
                cursor.execute(
                    """
                    ALTER TABLE devices
                    ADD COLUMN first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                    """
                )

            if not self._index_exists(cursor, "devices", "idx_devices_org_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_devices_org_last_seen
                    ON devices (organization_id, last_seen)
                    """
                )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS device_ip_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    device_mac VARCHAR(20) NOT NULL,
                    ip_address VARCHAR(50) NOT NULL,
                    organization_id CHAR(36),
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_device_ip_history (device_mac, ip_address, organization_id)
                )
                """
            )

            db_conn.commit()
            self._schema_ready = True
        finally:
            cursor.close()

    def get_devices(self, db_conn, organization_id: Optional[str] = None) -> List[dict]:
        self.ensure_schema(db_conn)
        managed = self._get_managed_devices(db_conn, organization_id)
        discovered_only = self._get_observed_devices(db_conn, organization_id)

        devices = self._merge_devices(managed + discovered_only)
        devices.sort(key=lambda d: d.get("last_seen") or "", reverse=True)
        return devices

    def _is_trackable_device_ip(self, ip: str | None) -> bool:
        return is_rfc1918_device_ip(ip)

    def _device_priority(self, device: dict) -> tuple:
        confidence_order = {"high": 2, "medium": 1, "low": 0}
        return (
            1 if device.get("management_mode") == "managed" else 0,
            confidence_order.get(device.get("confidence", "low"), 0),
            1 if normalize_mac(device.get("mac")) else 0,
            1 if device.get("hostname") not in {"Unknown", "Unnamed Device", None, ""} else 0,
            device.get("last_seen") or "",
        )

    def _device_identity_key(self, device: dict) -> Optional[str]:
        mac = normalize_mac(device.get("mac"))
        if mac:
            return f"mac:{mac}"
        ip = normalize_ip(device.get("ip"))
        if ip:
            return f"ip:{ip}"
        hostname = self._meaningful_value(device.get("hostname"), {"Unknown", "Unnamed Device", "-", ""})
        if hostname:
            return f"hostname:{hostname.lower()}"
        return None

    def _merge_devices(self, devices: List[dict]) -> List[dict]:
        merged: dict[str, dict] = {}
        for device in devices:
            identity_key = self._device_identity_key(device)
            if not identity_key:
                continue
            existing = merged.get(identity_key)
            if not existing or self._device_priority(device) > self._device_priority(existing):
                merged[identity_key] = device
        return list(merged.values())

    def _parse_timestamp(self, value) -> Optional[datetime]:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                return None
        return None

    def _format_timestamp(self, value) -> Optional[str]:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value) if value else None

    def get_device_status(self, last_seen) -> str:
        parsed = self._parse_timestamp(last_seen)
        if not parsed:
            return "Offline"

        age_seconds = max(int((datetime.now(timezone.utc) - parsed).total_seconds()), 0)
        if age_seconds < self.ONLINE_WINDOW_SECONDS:
            return "Online"
        if age_seconds < self.IDLE_WINDOW_SECONDS:
            return "Idle"
        return "Offline"

    def _meaningful_value(self, value, ignored: set[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = str(value).strip()
        if not normalized or normalized in ignored:
            return None
        return normalized

    def _find_existing_device(self, cursor, *, organization_id: Optional[str], mac: Optional[str], hostname: Optional[str], ip: str):
        if mac:
            cursor.execute(
                """
                SELECT *
                FROM devices
                WHERE mac = %s
                  AND (organization_id = %s OR (%s IS NULL AND organization_id IS NULL))
                ORDER BY id DESC
                LIMIT 1
                """,
                (mac, organization_id, organization_id),
            )
            existing = cursor.fetchone()
            if existing:
                return existing

        if hostname:
            cursor.execute(
                """
                SELECT *
                FROM devices
                WHERE hostname = %s
                  AND ip = %s
                  AND (organization_id = %s OR (%s IS NULL AND organization_id IS NULL))
                ORDER BY id DESC
                LIMIT 1
                """,
                (hostname, ip, organization_id, organization_id),
            )
            existing = cursor.fetchone()
            if existing:
                return existing

        cursor.execute(
            """
            SELECT *
            FROM devices
            WHERE ip = %s
              AND (organization_id = %s OR (%s IS NULL AND organization_id IS NULL))
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip, organization_id, organization_id),
        )
        return cursor.fetchone()

    def _record_ip_history(self, cursor, *, mac: Optional[str], ip: str, organization_id: Optional[str], seen_dt: datetime) -> None:
        if not mac:
            return
        cursor.execute(
            """
            INSERT INTO device_ip_history (
                device_mac,
                ip_address,
                organization_id,
                first_seen,
                last_seen
            )
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                last_seen = GREATEST(last_seen, VALUES(last_seen))
            """,
            (mac, ip, organization_id, seen_dt, seen_dt),
        )

    def touch_device_seen(
        self,
        db_conn,
        *,
        ip: str,
        organization_id: Optional[str] = None,
        seen_at=None,
        agent_id: Optional[str] = None,
        hostname: Optional[str] = None,
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        os_family: Optional[str] = None,
        create_if_missing: bool = False,
    ) -> bool:
        normalized_ip = normalize_ip(ip)
        if not self._is_trackable_device_ip(normalized_ip):
            return False

        self.ensure_schema(db_conn)
        seen_dt = self._parse_timestamp(seen_at) or datetime.now(timezone.utc)
        hostname_value = self._meaningful_value(hostname, {"Unknown", "Unknown-Device", "-"})
        mac_value = normalize_mac(mac)
        vendor_value = self._meaningful_value(vendor, {"Unknown", "-"})
        device_type_value = self._meaningful_value(device_type, {"Unknown", "Unknown Type", "-"})
        os_family_value = self._meaningful_value(os_family, {"Unknown", "-"})
        agent_id_value = self._meaningful_value(agent_id, {"Unknown", "-"})

        cursor = db_conn.cursor(dictionary=True)
        try:
            existing = self._find_existing_device(
                cursor,
                organization_id=organization_id,
                mac=mac_value,
                hostname=hostname_value,
                ip=normalized_ip,
            )
            if existing:
                existing_last_seen = self._parse_timestamp(existing.get("last_seen"))
                merged_last_seen = seen_dt if not existing_last_seen else max(existing_last_seen, seen_dt)
                merged_first_seen = existing.get("first_seen") or seen_dt
                cursor.execute(
                    """
                    UPDATE devices
                    SET
                        hostname = %s,
                        mac = %s,
                        ip = %s,
                        vendor = %s,
                        device_type = %s,
                        os_family = %s,
                        organization_id = %s,
                        agent_id = %s,
                        first_seen = %s,
                        last_seen = %s,
                        is_online = TRUE
                    WHERE id = %s
                    """,
                    (
                        hostname_value or existing.get("hostname") or "Unknown",
                        mac_value or normalize_mac(existing.get("mac")) or existing.get("mac"),
                        normalized_ip,
                        vendor_value or existing.get("vendor") or "Unknown",
                        device_type_value or existing.get("device_type") or "Unknown",
                        os_family_value or existing.get("os_family") or "Unknown",
                        existing.get("organization_id") or organization_id,
                        agent_id_value or existing.get("agent_id"),
                        merged_first_seen,
                        merged_last_seen,
                        existing["id"],
                    ),
                )
                self._record_ip_history(
                    cursor,
                    mac=mac_value or normalize_mac(existing.get("mac")),
                    ip=normalized_ip,
                    organization_id=existing.get("organization_id") or organization_id,
                    seen_dt=merged_last_seen,
                )
                return True

            if not create_if_missing or not mac_value:
                return False

            cursor.execute(
                """
                INSERT INTO devices (
                    ip,
                    mac,
                    hostname,
                    vendor,
                    device_type,
                    os_family,
                    is_online,
                    organization_id,
                    agent_id,
                    first_seen,
                    last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s)
                """,
                (
                    normalized_ip,
                    mac_value,
                    hostname_value or "Unknown",
                    vendor_value or "Unknown",
                    device_type_value or "Unknown",
                    os_family_value or "Unknown",
                    organization_id,
                    agent_id_value,
                    seen_dt,
                    seen_dt,
                ),
            )
            self._record_ip_history(
                cursor,
                mac=mac_value,
                ip=normalized_ip,
                organization_id=organization_id,
                seen_dt=seen_dt,
            )
            return True
        finally:
            cursor.close()

    def _get_managed_devices(self, db_conn, organization_id: Optional[str] = None) -> List[dict]:
        managed_device_service.ensure_table(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            query = """
                SELECT
                    md.agent_id AS id,
                    md.agent_id AS agent_id,
                    md.device_ip AS ip,
                    COALESCE(NULLIF(d.mac, ''), COALESCE(md.device_mac, '-')) AS mac,
                    COALESCE(NULLIF(d.hostname, 'Unknown'), COALESCE(md.hostname, 'Unknown')) AS hostname,
                    COALESCE(NULLIF(d.vendor, 'Unknown'), 'Managed Agent') AS vendor,
                    COALESCE(NULLIF(d.device_type, 'Unknown'), 'Managed Device') AS device_type,
                    COALESCE(NULLIF(d.os_family, 'Unknown'), COALESCE(md.os_family, 'Unknown')) AS os_family,
                    COALESCE(d.is_online, TRUE) AS is_online,
                    md.organization_id,
                    md.first_seen,
                    COALESCE(d.last_seen, md.last_seen) AS last_seen,
                    COALESCE(r.current_score, 0) AS risk_score,
                    COALESCE(r.risk_level, 'LOW') AS risk_level,
                    'high' AS confidence,
                    'managed' AS management_mode
                FROM managed_devices md
                LEFT JOIN device_risks r ON md.device_ip = r.device_id
                LEFT JOIN devices d
                    ON (
                        (NULLIF(d.mac, '') IS NOT NULL AND NULLIF(md.device_mac, '') IS NOT NULL AND d.mac = md.device_mac)
                        OR d.ip = md.device_ip
                    )
                    AND (d.organization_id = md.organization_id OR d.organization_id IS NULL)
            """

            params = []
            if organization_id:
                query += " WHERE md.organization_id = %s"
                params.append(organization_id)

            query += " ORDER BY md.last_seen DESC"
            cursor.execute(query, tuple(params))
            return self._format_device_rows(cursor.fetchall(), brand="Managed")
        finally:
            cursor.close()

    def _get_observed_devices(self, db_conn, organization_id: Optional[str] = None) -> List[dict]:
        managed_device_service.ensure_table(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            conditions = [
                "md.agent_id IS NULL",
                "NULLIF(d.mac, '') IS NOT NULL",
                "d.mac <> '-'",
            ]
            if organization_id:
                conditions.append("d.organization_id = %s")
                params.append(organization_id)

            query = """
                SELECT
                    COALESCE(d.agent_id, d.ip) AS id,
                    d.agent_id AS agent_id,
                    d.ip AS ip,
                    COALESCE(NULLIF(d.mac, ''), '-') AS mac,
                    COALESCE(NULLIF(d.hostname, 'Unknown'), 'Unknown') AS hostname,
                    COALESCE(NULLIF(d.vendor, 'Unknown'), 'Unknown') AS vendor,
                    COALESCE(NULLIF(d.device_type, 'Unknown'), 'Observed Device') AS device_type,
                    COALESCE(NULLIF(d.os_family, 'Unknown'), 'Unknown') AS os_family,
                    COALESCE(d.is_online, TRUE) AS is_online,
                    d.organization_id,
                    d.first_seen,
                    d.last_seen,
                    COALESCE(r.current_score, 0) AS risk_score,
                    COALESCE(r.risk_level, 'LOW') AS risk_level,
                    'medium' AS confidence,
                    'byod' AS management_mode
                FROM devices d
                LEFT JOIN device_risks r ON d.ip = r.device_id
                LEFT JOIN managed_devices md
                    ON (
                        (NULLIF(d.mac, '') IS NOT NULL AND NULLIF(md.device_mac, '') IS NOT NULL AND d.mac = md.device_mac)
                        OR d.ip = md.device_ip
                    )
                    AND (md.organization_id = d.organization_id OR md.organization_id IS NULL)
            """

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY d.last_seen DESC"
            cursor.execute(query, tuple(params))
            rows = [row for row in cursor.fetchall() if self._is_trackable_device_ip(row.get("ip"))]
            return self._format_device_rows(rows, brand="Observed")
        finally:
            cursor.close()

    def _format_device_rows(self, rows: List[dict], brand: str) -> List[dict]:
        for d in rows:
            status = self.get_device_status(d.get("last_seen"))
            d["status"] = status
            d["is_online"] = status == "Online"
            d["last_seen"] = self._format_timestamp(d.get("last_seen"))
            d["first_seen"] = self._format_timestamp(d.get("first_seen"))
            d["brand"] = brand
            d["mac_address"] = d.get("mac", "-")
        return rows

    def get_device_risk(self, db_conn, device_id: str) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM device_risks WHERE device_id = %s", (device_id,))
            return cursor.fetchone()
        finally:
            cursor.close()

    def mark_stale_devices_offline(self, db_conn, stale_minutes: int = 5):
        """Compatibility sync for the legacy is_online flag."""
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor()
        try:
            cursor.execute("""
                UPDATE devices 
                SET is_online = CASE
                    WHEN last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s SECOND) THEN TRUE
                    ELSE FALSE
                END
            """, (self.ONLINE_WINDOW_SECONDS,))
            db_conn.commit()
            affected = cursor.rowcount
            if affected > 0:
                logger.info("Synchronized online flag for %s device(s).", affected)
        finally:
            cursor.close()


device_service = DeviceService()
