import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv('NETVISOR_DB_HOST', 'localhost')
user = os.getenv('NETVISOR_DB_USER', 'root')
password = os.getenv('NETVISOR_DB_PASSWORD', '')

def audit_data():
    try:
        db = mysql.connector.connect(host=host, user=user, password=password)
        cursor = db.cursor()
        
        for dbname in ['network_analyzer', 'network_security']:
            print(f"\n--- {dbname} ---")
            cursor.execute(f"USE {dbname}")
            cursor.execute("SHOW TABLES")
            tables = [t[0] for t in cursor.fetchall()]
            
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"Table: {table:<20} | Rows: {count}")
                
        db.close()
    except Exception as e:
        print(f"Audit Error: {e}")

if __name__ == "__main__":
    audit_data()
