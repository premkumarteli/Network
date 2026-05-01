from typing import Optional

from .application_service import application_service
from .device_service import device_service


class DashboardService:
    def _format_timestamp(self, value) -> str:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value or "")

    def _format_bytes(self, byte_count: float) -> str:
        if byte_count >= 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        if byte_count >= 1024:
            return f"{byte_count / 1024:.1f} KB"
        return f"{int(byte_count)} B"

    def get_overview_stats(self, db_conn, organization_id: Optional[str] = None) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        try:
            devices = device_service.get_devices(db_conn, organization_id=organization_id)

            flow_filter = ""
            alert_filter = ""
            flow_params: list = []
            alert_params: list = []

            if organization_id:
                flow_filter = "organization_id = %s AND "
                alert_filter = "organization_id = %s AND "
                flow_params.append(organization_id)
                alert_params.append(organization_id)

            cursor.execute(
                f"""
                SELECT
                    COUNT(*) AS flows_24h,
                    COALESCE(SUM(byte_count), 0) AS bytes_24h
                FROM flow_logs
                WHERE {flow_filter}last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)
                """,
                tuple(flow_params),
            )
            flow_stats = cursor.fetchone() or {"flows_24h": 0, "bytes_24h": 0}

            # Bandwidth: look at last 1 minute instead of 5s to account for agent batching lag
            cursor.execute(
                f"""
                SELECT COALESCE(SUM(byte_count), 0) AS bandwidth_bytes
                FROM flow_logs
                WHERE {flow_filter}last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE)
                """,
                tuple(flow_params),
            )
            bandwidth_row = cursor.fetchone() or {"bandwidth_bytes": 0}

            cursor.execute(
                f"""
                SELECT COUNT(*) AS high_risk
                FROM alerts
                WHERE {alert_filter}severity IN ('HIGH', 'CRITICAL')
                  AND resolved = FALSE
                  AND timestamp >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)
                """,
                tuple(alert_params),
            )
            high_risk_row = cursor.fetchone() or {"high_risk": 0}

            cursor.execute(
                f"""
                SELECT severity, COUNT(*) AS count
                FROM alerts
                WHERE {"organization_id = %s AND " if organization_id else ""}resolved = FALSE
                  AND timestamp >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)
                GROUP BY severity
                """,
                tuple(alert_params),
            )
            risk_distribution = {
                row["severity"]: row["count"]
                for row in cursor.fetchall()
            }

            active_devices = [d for d in devices if d.get("is_online")]
            bandwidth_bytes = float(bandwidth_row.get("bandwidth_bytes") or 0)
            
            # Bandwidth value in Mbps (assuming 1 minute window)
            # bandwidth_bytes * 8 (bits) / 60 (seconds) / 1,000,000 (Megabits)
            bandwidth_mbps = round((bandwidth_bytes * 8) / (60 * 1000 * 1000), 4)

            return {
                "active_devices": len(active_devices),
                "total_devices": len(devices),
                "high_risk": int(high_risk_row.get("high_risk") or 0),
                "flows_24h": int(flow_stats.get("flows_24h") or 0),
                "bandwidth": self._format_bytes(bandwidth_bytes / 60) + "/s",
                "bandwidth_value": bandwidth_mbps,
                "risk_distribution": risk_distribution,
                "threat_summary": {
                    "total": sum(risk_distribution.values()),
                    "high_critical": int(high_risk_row.get("high_risk") or 0)
                }
            }
        finally:
            cursor.close()

    def get_traffic_history(self, db_conn, hours: int = 24, organization_id: Optional[str] = None) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            org_filter = ""
            if organization_id:
                org_filter = "organization_id = %s AND "
                params.append(organization_id)
            
            params.append(hours)
            
            cursor.execute(
                f"""
                SELECT 
                    DATE_FORMAT(last_seen, '%Y-%m-%d %H:00:00') as hour,
                    COUNT(*) as flow_count,
                    COALESCE(SUM(byte_count), 0) as byte_count
                FROM flow_logs
                WHERE {org_filter}last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
                GROUP BY hour
                ORDER BY hour ASC
                """,
                tuple(params)
            )
            return cursor.fetchall()
        finally:
            cursor.close()

    def get_device_activity_stats(self, db_conn, limit: int = 5, organization_id: Optional[str] = None) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            org_filter = ""
            if organization_id:
                org_filter = "WHERE organization_id = %s"
                params.append(organization_id)
            
            params.append(limit)
            
            cursor.execute(
                f"""
                SELECT 
                    src_ip, 
                    COUNT(*) as flow_count,
                    COALESCE(SUM(byte_count), 0) as byte_count
                FROM flow_logs
                {org_filter}
                GROUP BY src_ip
                ORDER BY flow_count DESC
                LIMIT %s
                """,
                tuple(params)
            )
            return cursor.fetchall()
        finally:
            cursor.close()

    def get_recent_activity(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            query = """
                SELECT
                    f.last_seen,
                    f.src_ip,
                    f.dst_ip,
                    f.src_port,
                    f.dst_port,
                    f.external_endpoint_ip,
                    f.sni,
                    f.domain,
                    COALESCE(NULLIF(f.application, ''), 'Other') AS application,
                    f.protocol,
                    f.byte_count,
                    COALESCE(r.risk_level, 'LOW') AS severity,
                    CASE
                        WHEN md.agent_id IS NULL THEN 'byod'
                        ELSE 'managed'
                    END AS management_mode
                FROM flow_logs f
                LEFT JOIN device_risks r ON f.src_ip = r.device_id
                LEFT JOIN managed_devices md
                    ON f.src_ip = md.device_ip
                    AND (md.organization_id = f.organization_id OR md.organization_id IS NULL)
            """
            if organization_id:
                query += " WHERE f.organization_id = %s"
                params.append(organization_id)

            query += " ORDER BY f.last_seen DESC LIMIT %s"
            params.append(limit)
            cursor.execute(query, tuple(params))

            activity = []
            for row in cursor.fetchall():
                timestamp = self._format_timestamp(row.get("last_seen"))
                host = row.get("sni") or row.get("domain")
                application = application_service.resolve_application_label(row)
                activity.append(
                    {
                        "timestamp": timestamp,
                        "time": timestamp.split(" ")[-1] if timestamp else "",
                        "src_ip": row.get("src_ip"),
                        "dst_ip": row.get("dst_ip"),
                        "src_port": row.get("src_port"),
                        "dst_port": row.get("dst_port"),
                        "domain": host or "-",
                        "host": host or "-",
                        "external_endpoint_ip": row.get("external_endpoint_ip"),
                        "application": application or "Other",
                        "protocol": row.get("protocol") or "UNKNOWN",
                        "byte_count": float(row.get("byte_count") or 0),
                        "size": self._format_bytes(float(row.get("byte_count") or 0)),
                        "severity": row.get("severity") or "LOW",
                        "management_mode": row.get("management_mode") or "byod",
                    }
                )
            return activity
        finally:
            cursor.close()


dashboard_service = DashboardService()
