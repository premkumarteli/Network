import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv('NETVISOR_DB_HOST', 'localhost')
user = os.getenv('NETVISOR_DB_USER', 'root')
password = os.getenv('NETVISOR_DB_PASSWORD', '')

def migrate_users():
    try:
        db = mysql.connector.connect(host=host, user=user, password=password)
        cursor = db.cursor(dictionary=True)
        
        # 1. Fetch from network_analyzer
        print("Fetching users from network_analyzer...")
        cursor.execute("SELECT username, password, email, role FROM network_analyzer.users")
        legacy_users = cursor.fetchall()
        print(f"Found {len(legacy_users)} users.")
        
        # 2. Insert into network_security.users
        insert_sql = """
            INSERT IGNORE INTO network_security.users (username, password, email, role)
            VALUES (%s, %s, %s, %s)
        """
        
        vals = []
        for u in legacy_users:
            role = u['role'] if u['role'] else 'viewer'
            vals.append((u['username'], u['password'], u['email'], role))
            
        cursor.executemany(insert_sql, vals)
        db.commit()
        print(f"[SUCCESS] Migrated {len(vals)} user accounts.")
        
        db.close()
    except Exception as e:
        print(f"Migration Error: {e}")

if __name__ == "__main__":
    migrate_users()
