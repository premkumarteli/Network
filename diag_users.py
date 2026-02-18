import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

db_config = {
    "host": os.getenv("NETVISOR_DB_HOST", "localhost"),
    "user": os.getenv("NETVISOR_DB_USER", "root"),
    "password": os.getenv("NETVISOR_DB_PASSWORD", ""),
    "database": os.getenv("NETVISOR_DB_NAME", "network_security"),
}

def check_users():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, password, role FROM users")
        users = cursor.fetchall()
        print(f"Total users: {len(users)}")
        for u in users:
            pw = u['password']
            print(f"ID: {u['id']} | User: {u['username']} | Role: {u['role']}")
            print(f"   Password Hash: {pw}")
            print(f"   Length: {len(pw)} | StartsWith $2b$: {pw.startswith('$2b$')}")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_users()
