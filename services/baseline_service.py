from core.database import get_db_connection
import logging

logger = logging.getLogger("netvisor.baseline")

class BaselineService:
    def __init__(self):
        pass

    def compute_all_baselines(self):
        """
        Phase 2 & 3: Computes baselines based on flow data from the last 24 hours.
        Updated for hybrid flow architecture.
        """
        conn = get_db_connection()
        if not conn: return
        
        try:
            cursor = conn.cursor(dictionary=True)
            
            # 1. Use flow_logs to calculate behavioral averages
            # - avg_connections_per_min (Total flows / 1440 mins)
            # - avg_unique_destinations (Unique dst_ips)
            # - avg_flow_duration (Average of duration field)
            # - std_dev_connections (Using variance/stddev SQL functions)
            
            cursor.execute("""
                SELECT 
                    device_ip, 
                    organization_id,
                    COUNT(*) / (24 * 60) as avg_conn_rate,
                    COUNT(DISTINCT dst_ip) as unique_dsts,
                    AVG(duration) as avg_dur,
                    STDDEV(duration) as std_dev_dur
                FROM flow_logs
                WHERE last_seen > (NOW() - INTERVAL 1 DAY)
                GROUP BY device_ip, organization_id
            """)
            
            baselines = cursor.fetchall()
            
            for b in baselines:
                # 2. Update or Insert into device_baselines
                cursor.execute("""
                    INSERT INTO device_baselines (
                        device_id, organization_id, ip_address, 
                        avg_connections_per_min, avg_unique_destinations, 
                        avg_flow_duration, std_dev_connections, 
                        last_computed
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE
                        avg_connections_per_min = VALUES(avg_connections_per_min),
                        avg_unique_destinations = VALUES(avg_unique_destinations),
                        avg_flow_duration = VALUES(avg_flow_duration),
                        std_dev_connections = VALUES(std_dev_connections),
                        ip_address = VALUES(ip_address),
                        last_computed = NOW()
                """, (
                    b['device_ip'], b['organization_id'], b['device_ip'],
                    b['avg_conn_rate'], b['unique_dsts'], 
                    b['avg_dur'], b['std_dev_dur']
                ))
            
            conn.commit()
            print(f"[+] Recomputed flow baselines for {len(baselines)} devices.")
            
        except Exception as e:
            print(f"[-] Baseline Compute Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()

baseline_service = BaselineService()
