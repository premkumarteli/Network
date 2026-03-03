import mysql.connector
from mysql.connector import pooling
import os
import bcrypt
import asyncio
from colorama import Fore
import uuid
import ipaddress

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

def is_internal_ip(ip_str: str) -> bool:
    """Checks if an IP address is part of a private/local range."""
    try:
        if not ip_str or ip_str in ["-", "Unknown", "0.0.0.0"]:
            return False
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

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

            # 8. Device Baselines Table (Updated for Hybrid)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_baselines (
                    device_id VARCHAR(100) PRIMARY KEY,
                    organization_id CHAR(36),
                    ip_address VARCHAR(50),
                    avg_connections_per_min FLOAT DEFAULT 0.0,
                    avg_unique_destinations FLOAT DEFAULT 0.0,
                    avg_flow_duration FLOAT DEFAULT 0.0,
                    std_dev_connections FLOAT DEFAULT 0.0,
                    last_computed DATETIME DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_baseline_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 10. Risk History Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS risk_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36),
                    device_ip VARCHAR(50),
                    risk_score FLOAT,
                    severity VARCHAR(20),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_risk_hist_ip (device_ip),
                    CONSTRAINT fk_risk_hist_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            """)

            # 11. Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36),
                    device_ip VARCHAR(50),
                    severity VARCHAR(20),
                    risk_score FLOAT,
                    breakdown_json TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT FALSE,
                    INDEX idx_alert_ip (device_ip),
                    CONSTRAINT fk_alert_org FOREIGN KEY (organization_id) REFERENCES organizations(id)
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

            # 4b. Flow Logs Table (gateway / agent flow summaries)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36),
                    device_ip VARCHAR(50),
                    src_ip VARCHAR(50),
                    dst_ip VARCHAR(50),
                    src_port INT,
                    dst_port INT,
                    protocol VARCHAR(10),
                    start_time DATETIME,
                    last_seen DATETIME,
                    packet_count INT,
                    byte_count BIGINT,
                    duration FLOAT,
                    average_packet_size FLOAT,
                    domain VARCHAR(255),
                    agent_id VARCHAR(100),
                    INDEX idx_flow_device_time (device_ip, last_seen),
                    INDEX idx_flow_org_time (organization_id, last_seen)
                )
            """)

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
            add_column_if_missing("device_risks", "ip_address", "VARCHAR(50)")
            add_column_if_missing("device_baselines", "ip_address", "VARCHAR(50)")
            add_column_if_missing("device_baselines", "avg_connections_per_min", "FLOAT DEFAULT 0.0")
            add_column_if_missing("device_baselines", "avg_unique_destinations", "FLOAT DEFAULT 0.0")
            add_column_if_missing("device_baselines", "avg_flow_duration", "FLOAT DEFAULT 0.0")
            add_column_if_missing("device_baselines", "std_dev_connections", "FLOAT DEFAULT 0.0")
            add_column_if_missing("flow_logs", "domain", "VARCHAR(255)")

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

# --- SINGLE WRITER DB BUFFERS ---
packet_queue = asyncio.Queue(maxsize=10000)
flow_queue = asyncio.Queue(maxsize=10000)

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


async def flow_db_writer_worker():
    """
    Dedicated async worker for persisting flow summaries.
    Detection must NOT be performed here; this layer is ingestion only.
    """
    while True:
        logs = []
        log = await flow_queue.get()
        logs.append(log)

        while len(logs) < 200:
            try:
                log = flow_queue.get_nowait()
                logs.append(log)
            except asyncio.QueueEmpty:
                break

        if logs:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, write_flows_to_db, logs)

def write_logs_to_db(logs):
    from services.detector import detector
    conn = get_db_connection()
    if conn:
        try:
            print(f"DEBUG: write_logs_to_db processing {len(logs)} logs")
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
            # Mark tasks as done once after DB insertion
            for _ in range(len(logs)):
                packet_queue.task_done()


def write_flows_to_db(logs):
    """
    Persist flow summaries and trigger centralized detection.
    """
    from backend.detection.risk_engine import risk_engine
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            for l in logs:
                # 1. Store the flow
                sql = """
                    INSERT INTO flow_logs (
                        organization_id, device_ip, src_ip, dst_ip,
                        src_port, dst_port, protocol,
                        start_time, last_seen,
                        packet_count, byte_count, duration, average_packet_size,
                        domain, agent_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                # Normalize log object
                data = l.__dict__ if hasattr(l, '__dict__') else l
                
                vals = (
                    data.get("organization_id"), data.get("src_ip"), data.get("src_ip"), data.get("dst_ip"),
                    data.get("src_port"), data.get("dst_port"), data.get("protocol"),
                    data.get("start_time"), data.get("last_seen"),
                    data.get("packet_count"), data.get("byte_count"), data.get("duration"), 
                    data.get("average_packet_size"), data.get("domain"), data.get("agent_id")
                )
                cursor.execute(sql, vals)
                
                # 2. RUN DETECTION (Phase 2 Integration)
                # Fetch baseline
                cursor.execute("SELECT * FROM device_baselines WHERE device_id = %s", (data.get("src_ip"),))
                baseline = cursor.fetchone()
                
                # Evaluate Risk
                # We wrap the data in a simple object/struct if risk_engine expects it
                class FlowWrapper:
                    def __init__(self, d):
                        for k, v in d.items(): setattr(self, k, v)
                
                report = risk_engine.evaluate_flow(FlowWrapper(data), baseline)
                
                # 3. Persistence: Updates Risk & History
                # ONLY for internal assets
                if is_internal_ip(data.get("src_ip")):
                    cursor.execute("""
                        INSERT INTO device_risks (device_id, organization_id, ip_address, current_score, risk_level, reasons)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE 
                            current_score = VALUES(current_score),
                            risk_level = VALUES(risk_level),
                            reasons = VALUES(reasons)
                    """, (data.get("src_ip"), data.get("organization_id"), data.get("src_ip"), 
                         report["score"], report["severity"], ",".join(report["reasons"])))
                    
                    cursor.execute("""
                        INSERT INTO risk_history (organization_id, device_ip, risk_score, severity)
                        VALUES (%s, %s, %s, %s)
                    """, (data.get("organization_id"), data.get("src_ip"), report["score"], report["severity"]))
                
                # 4. Generate Alert if HIGH/CRITICAL
                if report["severity"] in ["HIGH", "CRITICAL"]:
                    cursor.execute("""
                        INSERT INTO alerts (organization_id, device_ip, severity, risk_score, breakdown_json)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (data.get("organization_id"), data.get("src_ip"), report["severity"], 
                         report["score"], json.dumps(report["breakdown"])))

            conn.commit()
            cursor.close()
        except Exception as e:
            print(f"Flow DB Worker Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            for _ in range(len(logs)):
                flow_queue.task_done()

# --- DATA ACCESS LAYER ---

def db_fetch_recent_traffic(limit=1000, severity=None, organization_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        # Bridge: Query flow_logs and join with device_risks for severity/score
        query = """
            SELECT 
                f.last_seen as timestamp,
                f.src_ip as source_ip,
                f.dst_ip,
                f.domain, 
                f.protocol,
                f.dst_port as port,
                r.current_score as risk_score,
                0.0 as entropy,
                r.risk_level as severity,
                f.agent_id,
                f.byte_count as packet_size,
                COALESCE(da.device_name, '-') as device_name,
                '-' as device_type,
                '-' as os_family,
                '-' as brand,
                f.src_ip as mac_address,
                'medium' as identity_confidence,
                f.organization_id
            FROM flow_logs f
            LEFT JOIN device_risks r ON f.src_ip = r.device_id
            LEFT JOIN device_aliases da ON f.src_ip = da.ip_address AND f.organization_id = da.organization_id
        """
        params = []
        conditions = []
        
        if organization_id:
            conditions.append("f.organization_id = %s")
            params.append(organization_id)
        if severity:
            conditions.append("r.risk_level = %s")
            params.append(severity)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY f.id DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        
        # Standardize date formatting for frontend
        for r in rows:
            if r.get("timestamp") and hasattr(r["timestamp"], "strftime"):
                r["timestamp"] = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        return rows
    except Exception:
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
        # Query the new alerts table for VPN related items
        query = "SELECT device_ip as source_ip, risk_score, timestamp, 'UDP' as protocol, severity FROM alerts WHERE breakdown_json LIKE '%vpn_score%'"
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
        rows = cursor.fetchall()
        
        # Standardize date formatting for frontend
        for r in rows:
            if r.get("last_updated") and hasattr(r["last_updated"], "strftime"):
                r["last_updated"] = r["last_updated"].strftime("%Y-%m-%d %H:%M:%S")
        return rows
    except Exception:
        return []
    finally:
        if conn: conn.close()

def db_truncate_tables():
    conn = get_db_connection()
    if not conn: return False
    try:
        cursor = conn.cursor()
        cursor.execute("TRUNCATE TABLE flow_logs")
        cursor.execute("TRUNCATE TABLE traffic_logs")
        cursor.execute("TRUNCATE TABLE activity_logs")
        cursor.execute("TRUNCATE TABLE alerts")
        cursor.execute("TRUNCATE TABLE risk_history")
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
