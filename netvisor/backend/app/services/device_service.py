from typing import List, Optional
import logging

logger = logging.getLogger("netvisor.devices")

class DeviceService:
    def get_devices(self, db_conn, organization_id: Optional[str] = None) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            query = """
                SELECT 
                    f.src_ip as ip,
                    f.src_ip as mac, -- Placeholder for MAC until discovery is full
                    COALESCE(da.device_name, 'Unknown') as hostname,
                    r.current_score as risk_score,
                    r.risk_level as risk_level,
                    MAX(f.last_seen) as last_seen,
                    'low' as confidence
                FROM flow_logs f
                LEFT JOIN device_risks r ON f.src_ip = r.device_id
                LEFT JOIN device_aliases da ON f.src_ip = da.ip_address AND f.organization_id = da.organization_id
            """
            params = []
            if organization_id:
                query += " WHERE f.organization_id = %s"
                params.append(organization_id)
            
            query += " GROUP BY f.src_ip"
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def get_device_risk(self, db_conn, device_id: str) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM device_risks WHERE device_id = %s", (device_id,))
            return cursor.fetchone()
        finally:
            cursor.close()

device_service = DeviceService()
