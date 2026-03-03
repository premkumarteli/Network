from typing import List
import logging
import json

logger = logging.getLogger("netvisor.services.alerts")

class AlertService:
    def get_alerts(self, db_conn, organization_id: str, limit: int = 50) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT * FROM alerts 
                WHERE organization_id = %s 
                ORDER BY timestamp DESC LIMIT %s
            """, (organization_id, limit))
            rows = cursor.fetchall()
            for r in rows:
                if r.get('breakdown_json'):
                    r['breakdown'] = json.loads(r['breakdown_json'])
            return rows
        finally:
            cursor.close()

    def get_risk_ranking(self, db_conn, organization_id: str, limit: int = 10) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT device_id, ip_address, current_score, risk_level, reasons
                FROM device_risks
                WHERE organization_id = %s
                ORDER BY current_score DESC LIMIT %s
            """, (organization_id, limit))
            return cursor.fetchall()
        finally:
            cursor.close()

alert_service = AlertService()
