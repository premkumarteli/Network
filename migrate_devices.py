import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv('NETVISOR_DB_HOST', 'localhost')
user = os.getenv('NETVISOR_DB_USER', 'root')
password = os.getenv('NETVISOR_DB_PASSWORD', '')

def migrate_devices():
    try:
        db = mysql.connector.connect(host=host, user=user, password=password)
        cursor = db.cursor(dictionary=True)
        
        # 1. Fetch from network_analyzer
        print("Fetching legacy devices...")
        cursor.execute("SELECT ip, hostname, vendor FROM network_analyzer.devices")
        legacy_devices = cursor.fetchall()
        print(f"Found {len(legacy_devices)} devices.")
        
        # 2. Insert into network_security.device_aliases
        insert_sql = """
            INSERT IGNORE INTO network_security.device_aliases (ip_address, device_name)
            VALUES (%s, %s)
        """
        
        vals = []
        for d in legacy_devices:
            name = d['hostname'] if d['hostname'] else d['vendor']
            if not name: name = "Generic Device"
            vals.append((d['ip'], name))
            
        cursor.executemany(insert_sql, vals)
        db.commit()
        print(f"[SUCCESS] Migrated {len(vals)} device aliases.")
        
        db.close()
    except Exception as e:
        print(f"Migration Error: {e}")

if __name__ == "__main__":
    migrate_devices()
