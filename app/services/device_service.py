from datetime import datetime, timezone
from typing import List, Optional
import logging

from ..core.config import settings
from ..db.session import require_runtime_schema
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

    ONLINE_WINDOW_SECONDS = 30   # 3x heartbeat interval (10s) to absorb normal latency
    IDLE_WINDOW_SECONDS = 120

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
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def get_devices(self, db_conn, organization_id: Optional[str] = None) -> List[dict]:
        self.ensure_schema(db_conn)
        managed = self._get_managed_devices(db_conn, organization_id)
        discovered_only = self._get_observed_devices(db_conn, organization_id)

        merged = self._merge_devices(managed + discovered_only)
        self._add_activity_snapshots(db_conn, merged)
        
        merged.sort(key=lambda d: d.get("last_seen") or "", reverse=True)
        return merged

    def _add_activity_snapshots(self, db_conn, devices: List[dict]):
        if not devices:
            return
        
        cursor = db_conn.cursor(dictionary=True)
        try:
            device_ips = [d.get("ip") for d in devices if d.get("ip")]
            if not device_ips:
                return

            # Batch query for latest session per device
            format_strings = ','.join(['%s'] * len(device_ips))
            query = f"""
                SELECT s.device_ip, s.application, s.domain, s.last_seen
                FROM sessions s
                INNER JOIN (
                    SELECT device_ip, MAX(last_seen) as max_seen
                    FROM sessions
                    WHERE device_ip IN ({format_strings})
                    GROUP BY device_ip
                ) m ON s.device_ip = m.device_ip AND s.last_seen = m.max_seen
            """
            cursor.execute(query, tuple(device_ips))
            snapshots = {row["device_ip"]: row for row in cursor.fetchall()}
            
            for device in devices:
                ip = device.get("ip")
                snap = snapshots.get(ip)
                if snap:
                    device["top_application"] = snap["application"]
                    device["top_domain"] = snap["domain"]
                    device["activity_last_seen"] = self._format_timestamp(snap["last_seen"])
                else:
                    device["top_application"] = None
                    device["top_domain"] = None
        except Exception as e:
            logger.error(f"Failed to fetch activity snapshots: {e}")
        finally:
            cursor.close()

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
        # Managed devices: identity is the agent, not the NIC.
        # This prevents multi-NIC hosts from creating duplicate entries.
        if device.get("management_mode") == "managed":
            agent_id = device.get("agent_id") or device.get("id")
            if agent_id:
                return f"agent:{agent_id}"

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
            is_new_device = existing is None
            
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
            else:
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
                
                # Audit log for new device discovery
                if organization_id:
                    try:
                        from ..services.audit_service import audit_service
                        audit_service.log_agent_registration(
                            organization_id=str(organization_id),
                            username="system",  # Device discovery is system-generated
                            agent_id=agent_id_value or "unknown",
                            action="device_discovered",
                            details=f"ip: {normalized_ip}; mac: {mac_value or 'unknown'}; hostname: {hostname_value or 'unknown'}"
                        )
                    except ImportError:
                        pass
                    except Exception as exc:
                        logger.debug(f"Audit logging failed for device discovery: {exc}")
            
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
