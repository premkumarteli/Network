import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv('NETVISOR_DB_HOST', 'localhost')
user = os.getenv('NETVISOR_DB_USER', 'root')
password = os.getenv('NETVISOR_DB_PASSWORD', '')

def audit_schemas():
    try:
        db = mysql.connector.connect(host=host, user=user, password=password)
        cursor = db.cursor()
        
        target_dbs = ['network_analyzer', 'network_security']
        for dbname in target_dbs:
            print(f"\n--- {dbname} ---")
            cursor.execute(f"USE {dbname}")
            cursor.execute("SHOW TABLES")
            tables = [t[0] for t in cursor.fetchall()]
            for table in tables:
                cursor.execute(f"DESCRIBE {table}")
                cols = [c[0] for c in cursor.fetchall()]
                print(f"Table: {table} | Cols: {cols}")
                
        db.close()
    except Exception as e:
        print(f"Audit Error: {e}")

if __name__ == "__main__":
    audit_schemas()
