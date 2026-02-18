import mysql.connector
import os
import bcrypt
import asyncio
from colorama import Fore
from .models import PacketLog

db_config = {
    "host": os.getenv("NETVISOR_DB_HOST", "localhost"),
    "user": os.getenv("NETVISOR_DB_USER", "root"),
    "password": os.getenv("NETVISOR_DB_PASSWORD", ""),
    "database": os.getenv("NETVISOR_DB_NAME", "network_security"),
}

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except Exception as exc:
        print(f"{Fore.RED}[X] DB connection error: {exc}")
        return None

def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(50),
                    device_name VARCHAR(100) DEFAULT 'Unknown',
                    domain VARCHAR(255),
                    protocol VARCHAR(20),
                    port VARCHAR(10) DEFAULT '53',
                    risk_score INT DEFAULT 0,
                    entropy FLOAT DEFAULT 0.0,
                    severity VARCHAR(20) DEFAULT 'LOW',
                    agent_id VARCHAR(100),
                    dst_ip VARCHAR(50) DEFAULT '-',
                    packet_size INT DEFAULT 0,
                    device_type VARCHAR(50) DEFAULT 'Unknown',
                    os_family VARCHAR(50) DEFAULT 'Unknown',
                    brand VARCHAR(50) DEFAULT 'Unknown'
                )
            """)
            
            # Ensure new columns exist
            cols = ["dst_ip", "packet_size", "device_type", "os_family", "brand"]
            cursor.execute("DESCRIBE traffic_logs")
            existing_cols = [c[0] for c in cursor.fetchall()]
            
            for col in cols:
                if col not in existing_cols:
                    if col == "packet_size":
                        cursor.execute(f"ALTER TABLE traffic_logs ADD COLUMN {col} INT DEFAULT 0")
                    else:
                        cursor.execute(f"ALTER TABLE traffic_logs ADD COLUMN {col} VARCHAR(50) DEFAULT 'Unknown'")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(100),
                    role VARCHAR(20) DEFAULT 'viewer'
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username VARCHAR(50),
                    action VARCHAR(255),
                    ip_address VARCHAR(50),
                    severity VARCHAR(20) DEFAULT 'INFO'
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_aliases (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(50) UNIQUE NOT NULL,
                    device_name VARCHAR(100) NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            admin_user = os.getenv("NETVISOR_BOOTSTRAP_ADMIN_USERNAME", "admin")
            admin_pass = os.getenv("NETVISOR_BOOTSTRAP_ADMIN_PASSWORD", "pppp")
            
            cursor.execute("SELECT password FROM users WHERE username = %s", (admin_user,))
            row = cursor.fetchone()
            if not row:
                hashed_admin_pass = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
                cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (admin_user, hashed_admin_pass, "admin"))
                conn.commit()
            else:
                current_hashed = row[0]
                if len(current_hashed) == 64 and not current_hashed.startswith("$2b$"):
                    new_hashed = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
                    cursor.execute("UPDATE users SET password = %s WHERE username = %s", (new_hashed, admin_user))
                    conn.commit()
                    print(f"{Fore.YELLOW}[!] Admin password upgraded to bcrypt.")
                
            cursor.close()
            conn.close()
            print(f"{Fore.GREEN}[!] Database initialized.")
        except Exception as e:
            print(f"{Fore.RED}[X] DB Init Error: {e}")

# --- SINGLE WRITER DB BUFFER ---
packet_queue = asyncio.Queue(maxsize=10000)

async def db_writer_worker():
    while True:
        logs = []
        log = await packet_queue.get()
        logs.append(log)
        
        while len(logs) < 100:
            try:
                log = packet_queue.get_nowait()
                logs.append(log)
            except asyncio.QueueEmpty:
                break
        
        if logs:
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    sql = "INSERT INTO traffic_logs (timestamp, source_ip, dst_ip, device_name, domain, protocol, port, risk_score, entropy, severity, agent_id, packet_size, device_type, os_family, brand) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    vals = [(
                        l.time, l.src_ip, l.dst_ip, l.device_name or "Unknown", l.domain, l.protocol, l.port,
                        l.risk_score, l.entropy, (l.severity or "LOW").upper(), l.agent_id, l.size,
                        l.device_type or "Unknown", l.os_family or "Unknown", l.brand or "Unknown"
                    ) for l in logs]
                    cursor.executemany(sql, vals)
                    conn.commit()
                    cursor.close()
                    conn.close()
                except Exception as e:
                    print(f"DB Worker Error: {e}")
                finally:
                    for _ in range(len(logs)):
                        packet_queue.task_done()
