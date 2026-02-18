import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv('NETVISOR_DB_HOST', 'localhost')
user = os.getenv('NETVISOR_DB_USER', 'root')
password = os.getenv('NETVISOR_DB_PASSWORD', '')

def migrate_data():
    try:
        db = mysql.connector.connect(host=host, user=user, password=password)
        cursor = db.cursor(dictionary=True)
        
        # 1. Fetch from network_analyzer
        print("Fetching legacy data from network_analyzer.activity...")
        cursor.execute("SELECT ip, time_str, domain, protocol, size FROM network_analyzer.activity")
        legacy_data = cursor.fetchall()
        print(f"Found {len(legacy_data)} records.")
        
        # 2. Insert into network_security.traffic_logs
        print("Inserting into network_security.traffic_logs...")
        insert_sql = """
            INSERT INTO network_security.traffic_logs 
            (timestamp, source_ip, domain, protocol, packet_size, device_name, device_type, os_family, brand, severity, risk_score, entropy, port, agent_id, dst_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        vals = []
        for row in legacy_data:
            vals.append((
                row['time_str'],
                row['ip'],
                row['domain'],
                row['protocol'],
                row['size'] if row['size'] else 0,
                "Historical",  # device_name
                "Unknown",     # device_type
                "Unknown",     # os_family
                "Unknown",     # brand
                "LOW",         # severity
                0,             # risk_score
                0.0,           # entropy
                0,             # port
                "LEGACY_RESTORE", # agent_id
                "-"            # dst_ip
            ))
            
        # Batch insert
        batch_size = 500
        for i in range(0, len(vals), batch_size):
            chunk = vals[i:i + batch_size]
            cursor.executemany(insert_sql, chunk)
            db.commit()
            print(f"Migrated {min(i + batch_size, len(vals))} / {len(vals)}...")

        print("\n[SUCCESS] Migration complete!")
        db.close()
    except Exception as e:
        print(f"Migration Error: {e}")

if __name__ == "__main__":
    migrate_data()
