from core.database import get_db_connection
import datetime
import json

class BaselineService:
    def __init__(self):
        pass

    def compute_all_baselines(self):
        """
        Computes baselines for all active devices based on the last 24 hours of traffic.
        """
        conn = get_db_connection()
        if not conn: return
        
        try:
            cursor = conn.cursor(dictionary=True)
            
            # 1. Identify active devices and calculate averages
            # We look at: Avg Packets per Minute, Avg Unique Domains per Hour
            cursor.execute("""
                SELECT 
                    mac_address, 
                    organization_id,
                    COUNT(*) / (24 * 60) as avg_packet_rate,
                    COUNT(DISTINCT domain) / 24 as avg_dns_per_hour,
                    COUNT(DISTINCT port) as avg_ports_used
                FROM traffic_logs
                WHERE timestamp > (NOW() - INTERVAL 1 DAY)
                AND mac_address != '-'
                GROUP BY mac_address, organization_id
            """)
            
            baselines = cursor.fetchall()
            
            for b in baselines:
                # 2. Update or Insert into device_baselines
                cursor.execute("""
                    INSERT INTO device_baselines (device_id, organization_id, avg_packet_rate, avg_dns_per_hour, avg_ports_used, last_computed)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE
                        avg_packet_rate = VALUES(avg_packet_rate),
                        avg_dns_per_hour = VALUES(avg_dns_per_hour),
                        avg_ports_used = VALUES(avg_ports_used),
                        last_computed = NOW()
                """, (b['mac_address'], b['organization_id'], b['avg_packet_rate'], b['avg_dns_per_hour'], b['avg_ports_used']))
            
            conn.commit()
            print(f"[+] Computed baselines for {len(baselines)} devices.")
            
        except Exception as e:
            print(f"[-] Baseline Compute Error: {e}")
        finally:
            conn.close()

baseline_service = BaselineService()
