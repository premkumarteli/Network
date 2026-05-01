from __future__ import annotations

import time
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging
import json

from ..core.config import settings
from ..db.session import require_runtime_schema
from .device_service import device_service
from .managed_device_service import managed_device_service

logger = logging.getLogger("netvisor.agent_monitoring")


class AgentService:
    def __init__(self) -> None:
        self._schema_ready = False
        self._inspection_cache_ttl_seconds = max(float(os.getenv("NETVISOR_HEALTH_CACHE_SECONDS", "10")), 0.0)
        self._inspection_observability_cache: dict[str, tuple[float, dict]] = {}

    def _invalidate_inspection_cache(self, organization_id: Optional[str] = None) -> None:
        if organization_id is None:
            self._inspection_observability_cache.clear()
            return
        self._inspection_observability_cache.pop(str(organization_id), None)

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
        cpu_usage: float = 0.0,
        ram_usage: float = 0.0,
    ) -> None:
        if not agent_id:
            return

        self.ensure_schema(db_conn)

        cursor = db_conn.cursor(dictionary=True)
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
            inspection_metrics_json = json.dumps(inspection_state.get("metrics") or {})

            # Check current CA installation status for audit logging
            previous_ca_installed = None
            if organization_id:  # Only check if we have an org_id (avoid checking during bootstrap)
                cursor.execute(
                    """
                    SELECT inspection_ca_installed FROM agents WHERE id = %s
                    """,
                    (agent_id,),
                )
                result = cursor.fetchone()
                if result:
                    previous_ca_installed = bool(result['inspection_ca_installed'])

            cursor.execute(
                """
                INSERT INTO agents (
                    id, name, hostname, api_key, organization_id, ip_address, os_family, version,
                    inspection_enabled, inspection_status, inspection_proxy_running, inspection_ca_installed,
                    inspection_browsers_json, inspection_last_error, inspection_metrics_json,
                    last_seen, cpu_usage, ram_usage
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(), %s, %s)
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
                    inspection_metrics_json = VALUES(inspection_metrics_json),
                    cpu_usage = VALUES(cpu_usage),
                    ram_usage = VALUES(ram_usage),
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
                    inspection_metrics_json,
                    cpu_usage,
                    ram_usage,
                ),
            )
            db_conn.commit()
            
            # Audit log for CA installation changes
            if organization_id and previous_ca_installed is not None:
                try:
                    from ..services.audit_service import audit_service
                    # We don't have easy access to username here since this is a service method
                    # In a real implementation, we might pass user context or use system auditing
                    if inspection_ca_installed != previous_ca_installed:
                        action = "ca_installed" if inspection_ca_installed else "ca_removed"
                        audit_service.log_ca_operation(
                            organization_id=str(organization_id),
                            username="system",  # Service-level action, not user-initiated
                            operation=action
                        )
                except ImportError:
                    # Audit service might not be available in all contexts
                    pass
                except Exception as exc:
                    # Don't let audit logging failures break the main operation
                    logger.debug(f"Audit logging failed for CA operation: {exc}")

            self._invalidate_inspection_cache(organization_id)
                    
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
        inspection_metrics = self._json_object(row.get("inspection_metrics_json"))

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
            "inspection_privacy_guard_enabled": bool(inspection_metrics.get("privacy_guard_enabled", True)),
            "inspection_sensitive_destination_bypass_enabled": bool(inspection_metrics.get("sensitive_destination_bypass_enabled", True)),
            "inspection_status": row.get("inspection_status") or "disabled",
            "inspection_proxy_running": bool(row.get("inspection_proxy_running")),
            "inspection_ca_installed": bool(row.get("inspection_ca_installed")),
            "inspection_browsers": self._json_list(row.get("inspection_browsers_json")),
            "inspection_last_error": row.get("inspection_last_error"),
            "inspection_ca_status": inspection_metrics.get("ca_status"),
            "inspection_thumbprint_sha256": inspection_metrics.get("thumbprint_sha256"),
            "inspection_cert_issued_at": inspection_metrics.get("issued_at"),
            "inspection_cert_expires_at": inspection_metrics.get("expires_at"),
            "inspection_rotation_due_at": inspection_metrics.get("rotation_due_at"),
            "inspection_days_until_expiry": inspection_metrics.get("days_until_expiry"),
            "inspection_days_until_rotation_due": inspection_metrics.get("days_until_rotation_due"),
            "inspection_expires_soon": bool(inspection_metrics.get("expires_soon")) if inspection_metrics.get("expires_soon") is not None else None,
            "inspection_rotation_due_soon": bool(inspection_metrics.get("rotation_due_soon")) if inspection_metrics.get("rotation_due_soon") is not None else None,
            "inspection_trust_store_match": bool(inspection_metrics.get("trust_store_match")),
            "inspection_trust_scope": inspection_metrics.get("trust_scope"),
            "inspection_key_protection": inspection_metrics.get("key_protection"),
            "inspection_proxy_pid": inspection_metrics.get("proxy_pid"),
            "inspection_proxy_port": inspection_metrics.get("proxy_port"),
            "inspection_queue_size": int(inspection_metrics.get("queue_size") or 0),
            "inspection_spooled_event_count": int(inspection_metrics.get("spooled_event_count") or 0),
            "inspection_dropped_event_count": int(inspection_metrics.get("dropped_event_count") or 0),
            "inspection_uploaded_event_count": int(inspection_metrics.get("uploaded_event_count") or 0),
            "inspection_upload_failures": int(inspection_metrics.get("upload_failures") or 0),
            "inspection_last_event_at": inspection_metrics.get("last_event_at"),
            "inspection_last_upload_at": inspection_metrics.get("last_upload_at"),
            "inspection_drop_reasons": inspection_metrics.get("drop_reasons") or {},
            "cpu_usage": float(row.get("cpu_usage") or 0.0),
            "ram_usage": float(row.get("ram_usage") or 0.0),
        }

    def _json_list(self, value) -> list[str]:
        if not value:
            return []
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return []
        return [str(item) for item in parsed if str(item).strip()]

    def _json_object(self, value) -> dict:
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _is_placeholder_agent_row(self, row: dict) -> bool:
        agent_id = str(row.get("agent_id") or row.get("id") or "").strip().upper()
        name = str(row.get("name") or "").strip().upper()
        hostname = str(row.get("hostname") or row.get("managed_hostname") or "").strip().lower()

        placeholder_prefixes = ("AGENT-TEST-", "TEST-", "DEMO-", "SAMPLE-", "FAKE-")
        placeholder_names = {"test", "demo", "sample", "fake", "placeholder"}

        if any(agent_id.startswith(prefix) for prefix in placeholder_prefixes):
            return True
        if any(name.startswith(prefix) for prefix in placeholder_prefixes):
            return True
        if hostname in placeholder_names:
            return True
        return False

    def _filter_placeholder_agents(self, rows: list[dict]) -> list[dict]:
        return [row for row in rows if not self._is_placeholder_agent_row(row)]

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
                    a.inspection_metrics_json,
                    a.organization_id,
                    a.last_seen,
                    a.cpu_usage,
                    a.ram_usage,
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
            return self._filter_placeholder_agents(cursor.fetchall())
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

    def get_inspection_observability(
        self,
        db_conn,
        organization_id: Optional[str] = None,
    ) -> dict:
        cache_key = str(organization_id or "__all__")
        now = time.monotonic()
        cached = self._inspection_observability_cache.get(cache_key)
        if cached and (now - cached[0]) < self._inspection_cache_ttl_seconds:
            return dict(cached[1])

        rows = self._fetch_agents(db_conn, organization_id=organization_id)
        overview = {
            "agents_reporting": len(rows),
            "inspection_enabled_agents": 0,
            "proxy_running_agents": 0,
            "privacy_guard_enabled_agents": 0,
            "sensitive_destination_bypass_enabled_agents": 0,
            "queue_size_total": 0,
            "spooled_event_count_total": 0,
            "dropped_event_count_total": 0,
            "uploaded_event_count_total": 0,
            "upload_failures_total": 0,
            "last_event_at": None,
            "last_upload_at": None,
        }

        for row in rows:
            metrics = self._json_object(row.get("inspection_metrics_json"))
            if bool(row.get("inspection_enabled")):
                overview["inspection_enabled_agents"] += 1
            if bool(metrics.get("privacy_guard_enabled", True)):
                overview["privacy_guard_enabled_agents"] += 1
            if bool(metrics.get("sensitive_destination_bypass_enabled", True)):
                overview["sensitive_destination_bypass_enabled_agents"] += 1
            if bool(row.get("inspection_proxy_running")):
                overview["proxy_running_agents"] += 1
            overview["queue_size_total"] += int(metrics.get("queue_size") or 0)
            overview["spooled_event_count_total"] += int(metrics.get("spooled_event_count") or 0)
            overview["dropped_event_count_total"] += int(metrics.get("dropped_event_count") or 0)
            overview["uploaded_event_count_total"] += int(metrics.get("uploaded_event_count") or 0)
            overview["upload_failures_total"] += int(metrics.get("upload_failures") or 0)

            last_event_at = metrics.get("last_event_at")
            if last_event_at and (not overview["last_event_at"] or str(last_event_at) > str(overview["last_event_at"])):
                overview["last_event_at"] = last_event_at

            last_upload_at = metrics.get("last_upload_at")
            if last_upload_at and (not overview["last_upload_at"] or str(last_upload_at) > str(overview["last_upload_at"])):
                overview["last_upload_at"] = last_upload_at

        self._inspection_observability_cache[cache_key] = (now, dict(overview))
        return overview

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
