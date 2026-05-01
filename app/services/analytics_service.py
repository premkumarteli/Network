from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..db.session import require_runtime_schema
from ..utils.network import is_rfc1918_device_ip
from .application_service import application_service
from .device_service import device_service
from .flow_service import flow_service


class AnalyticsService:
    DEFAULT_WINDOW_HOURS = 24

    def __init__(self) -> None:
        self._schema_ready = False

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def _format_bytes(self, byte_count: float) -> str:
        if byte_count >= 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"
        if byte_count >= 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        if byte_count >= 1024:
            return f"{byte_count / 1024:.1f} KB"
        return f"{int(byte_count)} B"

    def _format_timestamp(self, value) -> str:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value or "")

    def _window_cutoff(self, hours: int) -> datetime:
        hours = max(int(hours or 0), 1)
        return datetime.now(timezone.utc) - timedelta(hours=hours)

    def _device_lookup(self, db_conn, organization_id: Optional[str]) -> dict[str, dict]:
        devices = device_service.get_devices(db_conn, organization_id=organization_id)
        lookup: dict[str, dict] = {}
        for device in devices:
            ip = str(device.get("ip") or "").strip()
            if ip:
                lookup[ip] = device
        return lookup

    def _fetch_device_rollup(self, db_conn, organization_id: Optional[str], hours: int, limit: int) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            query = """
                SELECT
                    COALESCE(NULLIF(internal_device_ip, ''), src_ip) AS device_ip,
                    COUNT(*) AS flow_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes,
                    COUNT(DISTINCT COALESCE(NULLIF(sni, ''), NULLIF(domain, ''), dst_ip)) AS distinct_targets,
                    MAX(COALESCE(last_seen, created_at)) AS last_seen
                FROM flow_logs
                WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
            """
            params.append(hours)
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY COALESCE(NULLIF(internal_device_ip, ''), src_ip)
                ORDER BY bandwidth_bytes DESC, flow_count DESC, last_seen DESC
                LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def _fetch_device_application_rollup(self, db_conn, organization_id: Optional[str], hours: int) -> dict[str, dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [hours]
            query = """
                SELECT
                    COALESCE(NULLIF(internal_device_ip, ''), src_ip) AS device_ip,
                    COALESCE(NULLIF(application, ''), 'Other') AS application,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes,
                    COUNT(*) AS flow_count
                FROM flow_logs
                WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY COALESCE(NULLIF(internal_device_ip, ''), src_ip), COALESCE(NULLIF(application, ''), 'Other')
                ORDER BY bandwidth_bytes DESC, flow_count DESC
            """
            cursor.execute(query, tuple(params))
            top_application_by_device: dict[str, dict] = {}
            for row in cursor.fetchall():
                device_ip = str(row.get("device_ip") or "").strip()
                if not device_ip or device_ip in top_application_by_device:
                    continue
                top_application_by_device[device_ip] = {
                    "application": row.get("application") or "Other",
                    "bandwidth_bytes": int(row.get("bandwidth_bytes") or 0),
                    "flow_count": int(row.get("flow_count") or 0),
                }
            return top_application_by_device
        finally:
            cursor.close()

    def _fetch_conversation_rollup(self, db_conn, organization_id: Optional[str], hours: int, limit: int) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [hours]
            query = """
                SELECT
                    src_ip,
                    dst_ip,
                    COALESCE(NULLIF(sni, ''), NULLIF(domain, ''), dst_ip) AS host,
                    COALESCE(NULLIF(application, ''), 'Other') AS application,
                    COALESCE(NULLIF(protocol, ''), 'UNKNOWN') AS protocol,
                    COUNT(*) AS flow_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes,
                    MAX(COALESCE(last_seen, created_at)) AS last_seen
                FROM flow_logs
                WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY src_ip, dst_ip, COALESCE(NULLIF(sni, ''), NULLIF(domain, ''), dst_ip), COALESCE(NULLIF(application, ''), 'Other'), COALESCE(NULLIF(protocol, ''), 'UNKNOWN')
                ORDER BY bandwidth_bytes DESC, flow_count DESC, last_seen DESC
                LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def _fetch_scope_rollup(self, db_conn, organization_id: Optional[str], hours: int, limit: int) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [hours]
            query = """
                SELECT
                    COALESCE(NULLIF(network_scope, ''), 'unknown') AS network_scope,
                    COUNT(*) AS flow_count,
                    COUNT(DISTINCT COALESCE(NULLIF(internal_device_ip, ''), src_ip)) AS device_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes,
                    MAX(COALESCE(last_seen, created_at)) AS last_seen
                FROM flow_logs
                WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY COALESCE(NULLIF(network_scope, ''), 'unknown')
                ORDER BY bandwidth_bytes DESC, flow_count DESC, last_seen DESC
                LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def _fetch_trend_rollup(self, db_conn, organization_id: Optional[str], hours: int) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [hours]
            query = """
                SELECT
                    DATE_FORMAT(COALESCE(last_seen, created_at), '%%Y-%%m-%%d %%H:00:00') AS bucket,
                    COUNT(*) AS flow_count,
                    COUNT(DISTINCT COALESCE(NULLIF(internal_device_ip, ''), src_ip)) AS device_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes
                FROM flow_logs
                WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY bucket
                ORDER BY bucket ASC
            """
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def _fetch_window_summary(self, db_conn, organization_id: Optional[str], hours: int) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [hours]
            query = """
                SELECT
                    COUNT(*) AS flow_count,
                    COUNT(DISTINCT COALESCE(NULLIF(internal_device_ip, ''), src_ip)) AS device_count,
                    COUNT(DISTINCT COALESCE(NULLIF(sni, ''), NULLIF(domain, ''), dst_ip)) AS host_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes
                FROM flow_logs
                WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            cursor.execute(query, tuple(params))
            return cursor.fetchone() or {}
        finally:
            cursor.close()

    def get_overview(self, db_conn, organization_id: Optional[str], hours: int = DEFAULT_WINDOW_HOURS, limit: int = 8) -> dict:
        self.ensure_schema(db_conn)
        window_hours = max(int(hours or 0), 1)
        limit = max(int(limit or 0), 1)
        device_lookup = self._device_lookup(db_conn, organization_id)
        top_devices_raw = self._fetch_device_rollup(db_conn, organization_id, window_hours, limit)
        top_devices_apps = self._fetch_device_application_rollup(db_conn, organization_id, window_hours)
        top_conversations = self._fetch_conversation_rollup(db_conn, organization_id, window_hours, limit)
        scope_summary = self._fetch_scope_rollup(db_conn, organization_id, window_hours, limit)
        traffic_trend = self._fetch_trend_rollup(db_conn, organization_id, window_hours)
        window_summary = self._fetch_window_summary(db_conn, organization_id, window_hours)
        top_applications = application_service.get_application_summary(
            db_conn,
            organization_id=organization_id,
            window_minutes=window_hours * 60,
        )[:limit]
        uncategorized_domains = application_service.get_top_other_domains(
            db_conn,
            organization_id=organization_id,
            limit=limit,
        )

        top_devices: list[dict] = []
        observed_device_count = 0
        for row in top_devices_raw:
            device_ip = str(row.get("device_ip") or "").strip()
            if not device_ip or not is_rfc1918_device_ip(device_ip):
                continue
            observed_device_count += 1
            flow_count = int(row.get("flow_count") or 0)
            bandwidth_bytes = int(row.get("bandwidth_bytes") or 0)
            device = device_lookup.get(device_ip, {})
            top_application = top_devices_apps.get(device_ip, {})
            top_devices.append(
                {
                    "device_ip": device_ip,
                    "hostname": device.get("hostname") or "Unknown",
                    "status": device.get("status") or "Offline",
                    "management_mode": device.get("management_mode") or "byod",
                    "flow_count": flow_count,
                    "bandwidth_bytes": bandwidth_bytes,
                    "bandwidth": self._format_bytes(float(bandwidth_bytes)),
                    "distinct_targets": int(row.get("distinct_targets") or 0),
                    "last_seen": self._format_timestamp(row.get("last_seen")),
                    "top_application": top_application.get("application") or "Other",
                    "top_application_bandwidth_bytes": int(top_application.get("bandwidth_bytes") or 0),
                }
            )

        summary = {
            "window_hours": window_hours,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "flow_count": int(window_summary.get("flow_count") or 0),
            "bandwidth_bytes": int(window_summary.get("bandwidth_bytes") or 0),
            "bandwidth": self._format_bytes(float(window_summary.get("bandwidth_bytes") or 0)),
            "observed_device_count": int(window_summary.get("device_count") or 0),
            "fleet_device_count": len(device_lookup),
            "host_count": int(window_summary.get("host_count") or 0),
            "top_application": top_applications[0]["application"] if top_applications else "Unknown",
            "top_conversation": (
                f"{top_conversations[0].get('src_ip') or '-'} -> {top_conversations[0].get('dst_ip') or '-'}"
                if top_conversations
                else "-"
            ),
            "top_scope": scope_summary[0].get("network_scope") if scope_summary else "unknown",
        }

        return {
            "summary": summary,
            "top_applications": top_applications,
            "top_devices": top_devices,
            "top_conversations": [
                {
                    "src_ip": row.get("src_ip"),
                    "dst_ip": row.get("dst_ip"),
                    "host": row.get("host") or row.get("dst_ip") or "-",
                    "application": row.get("application") or "Other",
                    "protocol": row.get("protocol") or "UNKNOWN",
                    "flow_count": int(row.get("flow_count") or 0),
                    "bandwidth_bytes": int(row.get("bandwidth_bytes") or 0),
                    "bandwidth": self._format_bytes(float(row.get("bandwidth_bytes") or 0)),
                    "last_seen": self._format_timestamp(row.get("last_seen")),
                }
                for row in top_conversations
            ],
            "traffic_scopes": [
                {
                    "network_scope": row.get("network_scope") or "unknown",
                    "flow_count": int(row.get("flow_count") or 0),
                    "device_count": int(row.get("device_count") or 0),
                    "bandwidth_bytes": int(row.get("bandwidth_bytes") or 0),
                    "bandwidth": self._format_bytes(float(row.get("bandwidth_bytes") or 0)),
                    "last_seen": self._format_timestamp(row.get("last_seen")),
                }
                for row in scope_summary
            ],
            "traffic_trend": [
                {
                    "bucket": row.get("bucket"),
                    "flow_count": int(row.get("flow_count") or 0),
                    "device_count": int(row.get("device_count") or 0),
                    "bandwidth_bytes": int(row.get("bandwidth_bytes") or 0),
                    "bandwidth": self._format_bytes(float(row.get("bandwidth_bytes") or 0)),
                }
                for row in traffic_trend
            ],
            "uncategorized_domains": uncategorized_domains,
        }

    def _render_csv(self, rows: list[dict]) -> str:
        output = io.StringIO()
        if not rows:
            return ""
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: self._format_timestamp(value) if hasattr(value, "strftime") else value for key, value in row.items()})
        return output.getvalue()

    def export_dataset(
        self,
        db_conn,
        *,
        kind: str,
        organization_id: Optional[str],
        hours: int = DEFAULT_WINDOW_HOURS,
        limit: int = 5000,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        application: str | None = None,
        search: str | None = None,
    ) -> dict:
        self.ensure_schema(db_conn)
        normalized_kind = str(kind or "").strip().lower().replace("-", "_")
        hours = max(int(hours or 0), 1)
        limit = max(int(limit or 0), 1)

        if normalized_kind == "flows":
            result = flow_service.get_flow_logs(
                db_conn,
                organization_id=organization_id,
                limit=limit,
                offset=0,
                src_ip=src_ip,
                dst_ip=dst_ip,
                application=application,
                search=search,
            )
            rows = result.get("results") or []
            csv_text = self._render_csv(rows)
            return {
                "filename": "netvisor-flow-logs.csv",
                "rows": rows,
                "content": csv_text,
            }

        overview = self.get_overview(db_conn, organization_id=organization_id, hours=hours, limit=limit)
        dataset_map = {
            "apps": overview["top_applications"],
            "top_applications": overview["top_applications"],
            "devices": overview["top_devices"],
            "top_devices": overview["top_devices"],
            "conversations": overview["top_conversations"],
            "traffic_scopes": overview["traffic_scopes"],
            "scopes": overview["traffic_scopes"],
            "traffic_trend": overview["traffic_trend"],
            "trend": overview["traffic_trend"],
            "uncategorized_domains": overview["uncategorized_domains"],
        }
        rows = dataset_map.get(normalized_kind)
        if rows is None:
            raise ValueError(f"Unsupported export kind: {kind}")
        csv_text = self._render_csv(rows)
        return {
            "filename": f"netvisor-{normalized_kind}.csv",
            "rows": rows,
            "content": csv_text,
        }


analytics_service = AnalyticsService()
