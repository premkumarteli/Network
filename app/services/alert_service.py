from typing import List, Optional
import logging
import json

logger = logging.getLogger("netvisor.services.alerts")

class AlertService:
    def get_alerts(
        self,
        db_conn,
        organization_id: str,
        limit: int = 50,
        severities: Optional[List[str]] = None,
        resolved: Optional[bool] = None,
        hours: Optional[int] = None,
    ) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            conditions = ["organization_id = %s"]
            params: list = [organization_id]

            if severities:
                placeholders = ", ".join(["%s"] * len(severities))
                conditions.append(f"severity IN ({placeholders})")
                params.extend(severities)

            if resolved is not None:
                conditions.append("resolved = %s")
                params.append(resolved)

            if hours is not None and hours > 0:
                conditions.append("timestamp >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)")
                params.append(hours)

            query = f"""
                SELECT * FROM alerts
                WHERE {" AND ".join(conditions)}
                ORDER BY timestamp DESC LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            for r in rows:
                if r.get('breakdown_json'):
                    r['breakdown'] = json.loads(r['breakdown_json'])
                reasons = r.get("breakdown", {}).get("reasons", [])
                if reasons:
                    r["message"] = ", ".join(reasons)
                else:
                    r["message"] = f"{r.get('severity', 'LOW').title()} risk activity detected"
            return rows
        finally:
            cursor.close()

    def get_risk_ranking(self, db_conn, organization_id: str, limit: int = 10) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT device_id, device_id AS ip_address, current_score, risk_level, reasons
                FROM device_risks
                ORDER BY current_score DESC LIMIT %s
            """, (limit,))
            return cursor.fetchall()
        finally:
            cursor.close()

alert_service = AlertService()
