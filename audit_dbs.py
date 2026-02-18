import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv('NETVISOR_DB_HOST', 'localhost')
user = os.getenv('NETVISOR_DB_USER', 'root')
password = os.getenv('NETVISOR_DB_PASSWORD', '')

def audit_dbs():
    try:
        db = mysql.connector.connect(host=host, user=user, password=password)
        cursor = db.cursor()
        
        cursor.execute("SHOW DATABASES")
        databases = [d[0] for d in cursor.fetchall()]
        print(f"Available Databases: {databases}")
        
        target_dbs = ['netvisor', 'network_analyzer', 'network_security']
        for dbname in target_dbs:
            if dbname not in databases:
                print(f"DB '{dbname}' does not exist.")
                continue
                
            print(f"\n--- Auditing Database: {dbname} ---")
            cursor.execute(f"USE {dbname}")
            
            cursor.execute("SHOW TABLES")
            tables = [t[0] for t in cursor.fetchall()]
            print(f"Tables: {tables}")
            
            if 'users' in tables:
                cursor.execute("SELECT id, username, role FROM users")
                users = cursor.fetchall()
                print(f"Users found: {users}")
            else:
                print("No 'users' table found.")
                
        db.close()
    except Exception as e:
        print(f"Audit Error: {e}")

if __name__ == "__main__":
    audit_dbs()
