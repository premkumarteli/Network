import mysql.connector
from mysql.connector import pooling
import os
import bcrypt
import asyncio
from colorama import Fore
from .models import PacketLog
import uuid

db_config = {
    "host": os.getenv("NETVISOR_DB_HOST", "localhost"),
    "user": os.getenv("NETVISOR_DB_USER", "root"),
    "password": os.getenv("NETVISOR_DB_PASSWORD", ""),
    "database": os.getenv("NETVISOR_DB_NAME", "network_security"),
}

# Implementation of connection pooling for production-grade stability
try:
    pool = pooling.MySQLConnectionPool(
        pool_name="netvisor_pool",
        pool_size=10,
        **db_config
    )
    print(f"{Fore.GREEN}[+] Managed DB connection pool initialized (Size: 10).")
except Exception as e:
    print(f"{Fore.RED}[X] Failed to initialize connection pool: {e}")
    # Fallback to direct connection if pool fails (though not ideal)
    pool = None

def get_db_connection():
    try:
        if pool:
            return pool.get_connection()
        return mysql.connector.connect(**db_config)
    except Exception as exc:
        print(f"{Fore.RED}[X] DB connection error: {exc}")
        return None

def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            
            # 1. Organizations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id CHAR(36) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    status VARCHAR(20) DEFAULT 'active',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 2. Users Table (Revamped)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id CHAR(36) PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(100),
                    role VARCHAR(20) DEFAULT 'user',
                    organization_id CHAR(36),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_user_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 3. Agents Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id CHAR(36) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    api_key TEXT NOT NULL,
                    organization_id CHAR(36),
                    last_seen DATETIME,
                    CONSTRAINT fk_agent_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 4. Traffic Logs Table (Multi-tenant)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36),
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
                    brand VARCHAR(50) DEFAULT 'Unknown',
                    mac_address VARCHAR(50) DEFAULT '-',
                    identity_confidence VARCHAR(20) DEFAULT 'low',
                    CONSTRAINT fk_traffic_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 5. Activity Logs Table (Multi-tenant)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username VARCHAR(50),
                    action VARCHAR(255),
                    ip_address VARCHAR(50),
                    severity VARCHAR(20) DEFAULT 'INFO',
                    CONSTRAINT fk_activity_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 6. Device Aliases Table (Multi-tenant)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_aliases (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36),
                    ip_address VARCHAR(50) NOT NULL,
                    device_name VARCHAR(100) NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE(organization_id, ip_address),
                    CONSTRAINT fk_device_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 7. Device Risk Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_risks (
                    device_id VARCHAR(100) PRIMARY KEY,
                    organization_id CHAR(36),
                    ip_address VARCHAR(50),
                    current_score FLOAT DEFAULT 0.0,
                    risk_level VARCHAR(20) DEFAULT 'LOW',
                    reasons TEXT,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    CONSTRAINT fk_risk_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 8. Device Baselines Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_baselines (
                    device_id VARCHAR(100) PRIMARY KEY,
                    organization_id CHAR(36),
                    avg_packet_rate FLOAT DEFAULT 0.0,
                    avg_dns_per_hour FLOAT DEFAULT 0.0,
                    avg_ports_used INT DEFAULT 0,
                    active_hours_pattern TEXT,
                    last_computed DATETIME DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_baseline_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 9. Security Policies Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_policies (
                    organization_id CHAR(36) PRIMARY KEY,
                    blocked_domains TEXT,
                    vpn_restriction BOOLEAN DEFAULT FALSE,
                    alert_threshold INT DEFAULT 70,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    CONSTRAINT fk_policy_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            conn.commit()

            # --- HELPER: Ensure Columns exist ---
            def add_column_if_missing(table, col, col_def):
                cursor.execute(f"DESCRIBE {table}")
                existing = [c[0] for c in cursor.fetchall()]
                if col not in existing:
                    print(f"[*] Adding {col} to {table}...")
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")

            add_column_if_missing("traffic_logs", "organization_id", "CHAR(36)")
            add_column_if_missing("activity_logs", "organization_id", "CHAR(36)")
            add_column_if_missing("device_aliases", "organization_id", "CHAR(36)")

            # Upgrade Users table ID to CHAR(36) if still INT
            cursor.execute("DESCRIBE users")
            user_cols = cursor.fetchall()
            id_col = next(c for c in user_cols if c[0] == 'id')
            if 'int' in id_col[1].lower():
                print("[!] Migrating users table to UUID IDs...")
                # This is tricky with FKs, but since we are just starting SaaS refactor, we can be aggressive
                cursor.execute("ALTER TABLE users MODIFY id CHAR(36)")
            
            add_column_if_missing("users", "organization_id", "CHAR(36)")

            conn.commit()

            # --- MIGRATION & BOOTSTRAP ---
            
            cursor.execute("SELECT id FROM organizations WHERE name = 'Default Organization' LIMIT 1")
            org_row = cursor.fetchone()
            if not org_row:
                default_org_id = str(uuid.uuid4())
                cursor.execute("INSERT INTO organizations (id, name, status) VALUES (%s, %s, %s)", 
                               (default_org_id, "Default Organization", "active"))
                conn.commit()
                print(f"{Fore.CYAN}[*] Created Default Organization: {default_org_id}")
            else:
                default_org_id = org_row[0]

            admin_user = os.environ.get("NETVISOR_BOOTSTRAP_ADMIN_USERNAME", "admin")
            admin_pass = os.environ.get("NETVISOR_BOOTSTRAP_ADMIN_PASSWORD")
            
            if admin_pass:
                cursor.execute("SELECT password, id FROM users WHERE username = %s", (admin_user,))
                user_row = cursor.fetchone()
                if not user_row:
                    hashed_pass = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
                    cursor.execute("INSERT INTO users (id, username, password, role, organization_id) VALUES (%s, %s, %s, %s, %s)", 
                                   (str(uuid.uuid4()), admin_user, hashed_pass, "super_admin", default_org_id))
                    conn.commit()
                    print(f"{Fore.GREEN}[+] Super Admin bootstrapped.")
                else:
                    cursor.execute("UPDATE users SET role = 'super_admin', organization_id = %s WHERE username = %s AND organization_id IS NULL", 
                                   (default_org_id, admin_user))
                    conn.commit()

            # performance indexes
            try:
                cursor.execute("CREATE INDEX idx_traffic_org ON traffic_logs(organization_id)")
                cursor.execute("CREATE INDEX idx_time ON traffic_logs(timestamp)")
                cursor.execute("CREATE INDEX idx_user_org ON users(organization_id)")
            except: pass

            cursor.close()
            print(f"{Fore.GREEN}[!] Database initialized for Multi-Tenancy.")
        except Exception as e:
            print(f"{Fore.RED}[X] DB Init Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    print(f"DB Close Error: {e}")

# --- SINGLE WRITER DB BUFFER ---
packet_queue = asyncio.Queue(maxsize=10000)

async def drain_packet_queue():
    """Drains all remaining items in the queue to the database before shutdown."""
    print(f"{Fore.YELLOW}[!] Draining {packet_queue.qsize()} logs to DB...")
    while not packet_queue.empty():
        logs = []
        try:
            while len(logs) < 500:
                try:
                    logs.append(packet_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            
            if logs:
                write_logs_to_db(logs)
                for _ in range(len(logs)):
                    packet_queue.task_done()
        except Exception as e:
            print(f"Drain error: {e}")
            break
    print(f"{Fore.GREEN}[+] Queue drained successfully.")

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
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, write_logs_to_db, logs)
            
            # Always mark tasks as done
            for _ in range(len(logs)):
                packet_queue.task_done()

def write_logs_to_db(logs):
    from services.detector import detector
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            
            # Process logs through detection engine before saving
            enriched_logs = []
            for l in logs:
                # Dynamic detection
                score, entropy, severity, ml_prob, reasons = detector.analyze_packet(
                    domain=l.domain,
                    src_ip=l.src_ip,
                    dst_ip=l.dst_ip,
                    port=l.port,
                    device_id=l.mac_address # Using MAC as device ID for now
                )
                l.risk_score = int(score)
                l.entropy = entropy
                l.severity = severity
                enriched_logs.append(l)

            sql = "INSERT INTO traffic_logs (timestamp, source_ip, dst_ip, device_name, domain, protocol, port, risk_score, entropy, severity, agent_id, packet_size, device_type, os_family, brand, mac_address, identity_confidence, organization_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            vals = [(
                l.time, l.src_ip, l.dst_ip, l.device_name or "Unknown", l.domain, l.protocol, l.port,
                l.risk_score, l.entropy, (l.severity or "LOW").upper(), l.agent_id, l.size,
                l.device_type or "Unknown", l.os_family or "Unknown", l.brand or "Unknown",
                l.mac_address or "-", l.identity_confidence or "low", l.organization_id
            ) for l in enriched_logs]
            cursor.executemany(sql, vals)
            
            # Update Device Risk Table
            for l in enriched_logs:
                if l.mac_address and l.mac_address != "-":
                    cursor.execute("""
                        INSERT INTO device_risks (device_id, organization_id, ip_address, current_score, risk_level, reasons)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE 
                            current_score = VALUES(current_score),
                            risk_level = VALUES(risk_level),
                            reasons = VALUES(reasons),
                            ip_address = VALUES(ip_address)
                    """, (l.mac_address, l.organization_id, l.src_ip, l.risk_score, l.severity, ",".join(reasons)))

            conn.commit()
            cursor.close()
        except Exception as e:
            print(f"DB Worker Error: {e}")
        finally:
            conn.close()
            
            # Always mark tasks as done, even if DB write failed (logs dropped)
            for _ in range(len(logs)):
                packet_queue.task_done()

# --- DATA ACCESS LAYER ---

def db_fetch_recent_traffic(limit=1000, severity=None, organization_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM traffic_logs"
        params = []
        conditions = []
        
        if organization_id:
            conditions.append("organization_id = %s")
            params.append(organization_id)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    except Exception as e:
        print(f"DB Fetch Error: {e}")
        return []
    finally:
        if conn: conn.close()

def db_fetch_system_logs(limit=50, organization_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM activity_logs"
        params = []
        if organization_id:
            query += " WHERE organization_id = %s"
            params.append(organization_id)
        query += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    except Exception as e:
        print(f"Stats Fetch Error: {e}")
        return []
    finally:
        if conn: conn.close()

def db_fetch_vpn_alerts(limit=50, organization_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM traffic_logs WHERE (severity='HIGH' OR risk_score > 70)"
        params = []
        if organization_id:
            query += " AND organization_id = %s"
            params.append(organization_id)
        query += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    except Exception as e:
        print(f"VPN Fetch Error: {e}")
        return []
    finally:
        if conn: conn.close()

def db_fetch_device_risks(organization_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM device_risks"
        params = []
        if organization_id:
            query += " WHERE organization_id = %s"
            params.append(organization_id)
        
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    except Exception as e:
        print(f"DB Fetch Risks Error: {e}")
        return []
    finally:
        if conn: conn.close()

def db_truncate_tables():
    conn = get_db_connection()
    if not conn: return False
    try:
        cursor = conn.cursor()
        cursor.execute("TRUNCATE TABLE traffic_logs")
        cursor.execute("TRUNCATE TABLE activity_logs")
        conn.commit()
        return True
    except Exception as e:
        print(f"Truncate Error: {e}")
        return False
    finally:
        if conn: conn.close()

def db_export_to_csv():
    import csv
    import datetime
    
    if not os.path.exists("data/backups"):
        os.makedirs("data/backups")
        
    conn = get_db_connection()
    if not conn: return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM traffic_logs")
        rows = cursor.fetchall()
        if not rows: return "empty"
        
        filename = f"data/backups/traffic_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return filename
    except Exception as e:
        print(f"Export Error: {e}")
        return None
    finally:
        if conn: conn.close()
