import mysql.connector
from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Optional, List, Dict, Tuple
import uvicorn
import os
import datetime
import time
import psutil
import re
import socket
import csv
import bcrypt
from collections import Counter
import asyncio
from starlette.middleware.sessions import SessionMiddleware
from colorama import Fore, init

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize terminal colors
init(autoreset=True)

class PacketLog(BaseModel):
    time: str
    src_ip: str
    dst_ip: Optional[str] = "-"
    domain: str
    protocol: Optional[str] = "DNS"
    port: Optional[str] = "53"
    risk_score: Optional[int] = 0
    entropy: Optional[float] = 0.0
    severity: Optional[str] = "LOW"
    size: Optional[int] = 0
    agent_id: Optional[str] = "GATEWAY_SENSE_01"
    device_name: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    os_family: Optional[str] = "Unknown"
    brand: Optional[str] = "Unknown"

class HotspotRequest(BaseModel):
    action: str

class SystemConfigRequest(BaseModel):
    active: bool

class AgentRegistration(BaseModel):
    agent_id: str
    os: str
    hostname: str
    version: str
    time: str

class AgentHeartbeat(BaseModel):
    agent_id: str
    status: str
    dropped_packets: int
    time: str

# --- DATABASE CONFIG ---
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

def export_to_csv_task():
    """Helper to dump DB to CSV."""
    if not os.path.exists("backups"):
        os.makedirs("backups")
    conn = get_db_connection()
    if not conn: return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM traffic_logs")
        rows = cursor.fetchall()
        if not rows: return "empty"
        
        filename = f"backups/traffic_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return filename
    except Exception as e:
        print(f"Export error: {e}")
        return None
    finally:
        if conn: conn.close()

def truncate_data():
    """Wipe traffic and activity logs."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("TRUNCATE TABLE traffic_logs")
            cursor.execute("TRUNCATE TABLE activity_logs")
            conn.commit()
            return True
        except Exception as e:
            print(f"Truncate error: {e}")
        finally:
            conn.close()
    return False

def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp VARCHAR(50),
                    source_ip VARCHAR(50),
                    device_name VARCHAR(50),
                    domain VARCHAR(255),
                    protocol VARCHAR(10),
                    port VARCHAR(10),
                    risk_score INT,
                    entropy FLOAT,
                    severity VARCHAR(20),
                    agent_id VARCHAR(100),
                    dst_ip VARCHAR(50) DEFAULT '-',
                    packet_size INT DEFAULT 0,
                    device_type VARCHAR(50) DEFAULT 'Unknown',
                    os_family VARCHAR(50) DEFAULT 'Unknown',
                    brand VARCHAR(50) DEFAULT 'Unknown'
                )
            """)
            # Ensure new columns exist
            try: cursor.execute("ALTER TABLE traffic_logs ADD COLUMN dst_ip VARCHAR(50) DEFAULT '-'")
            except: pass
            try: cursor.execute("ALTER TABLE traffic_logs ADD COLUMN packet_size INT DEFAULT 0")
            except: pass
            try: cursor.execute("ALTER TABLE traffic_logs ADD COLUMN device_type VARCHAR(50) DEFAULT 'Unknown'")
            except: pass
            try: cursor.execute("ALTER TABLE traffic_logs ADD COLUMN os_family VARCHAR(50) DEFAULT 'Unknown'")
            except: pass
            try: cursor.execute("ALTER TABLE traffic_logs ADD COLUMN brand VARCHAR(50) DEFAULT 'Unknown'")
            except: pass

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
                # Upgrade if it looks like SHA256 (64 chars) and not bcrypt
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
    """Background task to empty the packet queue into the DB."""
    while True:
        logs = []
        # Wait for at least one item
        log = await packet_queue.get()
        logs.append(log)
        
        # Try to pull more if available (batching)
        while len(logs) < 100:
            try:
                log = packet_queue.get_nowait()
                logs.append(log)
            except asyncio.QueueEmpty:
                break
        
        # Batch insert
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
                    if conn: conn.close()
        
        for _ in range(len(logs)):
            packet_queue.task_done()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Start DB Worker
    asyncio.create_task(db_writer_worker())
    
    if not os.path.exists("backups"):
        os.makedirs("backups")
    print(f"{Fore.GREEN}[+] Netvisor Server is online.")
    yield
    # AUTO-BACKUP AND TRUNCATE ON SHUTDOWN
    print(f"\n{Fore.YELLOW}[!] Server stopping: Performing auto-backup and truncation...")
    file = export_to_csv_task()
    if file and file != "empty":
        print(f"{Fore.CYAN}[+] Backup saved: {file}")
    if truncate_data():
        print(f"{Fore.GREEN}[+] Data truncated. Next run will start fresh.")
    else:
        print(f"{Fore.RED}[X] Truncation failed.")

app = FastAPI(title="Netvisor | SOC Server", lifespan=lifespan)

SECRET_KEY = os.getenv("NETVISOR_SECRET_KEY", "change-me-in-env")

START_TIME = time.time()
MAINTENANCE_MODE = False
MONITORING_ACTIVE = True
HOTSPOT_ACTIVE = False
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "soc-agent-key-2026")

def validate_agent_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != AGENT_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return True

@app.middleware("http")
async def maintenance_middleware(request: Request, call_next):
    exempt_paths = ["/maintenance", "/login", "/register", "/forgot-password", "/static", "/api/v1/collect"]
    if MAINTENANCE_MODE and not any(request.url.path.startswith(p) for p in exempt_paths):
        if "user_id" not in request.session:
            return RedirectResponse(url="/maintenance")
    return await call_next(request)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def fastapi_url_for_compat(request: Request):
    def _url_for(name: str, **path_params):
        if name == 'static' and 'filename' in path_params:
            path_params['path'] = path_params.pop('filename')
        return request.url_for(name, **path_params)
    return _url_for

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password, hashed_password):
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except:
        return False

def parse_timestamp(value) -> datetime.datetime:
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value
    if not value or str(value).strip() == "" or str(value).lower() == "none":
        return datetime.datetime.now(datetime.timezone.utc)
    val_str = str(value)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            dt = datetime.datetime.strptime(val_str, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return datetime.datetime.now(datetime.timezone.utc)

def login_required(request: Request):
    if "user_id" not in request.session:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return request.session.get("username")

def admin_required(request: Request):
    if "user_id" not in request.session:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if request.session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Admin access required")
    return request.session.get("username")

def fetch_recent_traffic(limit=1000):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT %s", (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except: return []

# --- API ENDPOINTS ---

@app.post("/api/v1/collect/register")
async def register_agent(reg: AgentRegistration, auth: bool = Depends(validate_agent_key)):
    print(f"{Fore.CYAN}[+] Agent Registered: {reg.agent_id} ({reg.hostname})")
    return {"status": "success"}

@app.post("/api/v1/collect/heartbeat")
async def agent_heartbeat(hb: AgentHeartbeat, auth: bool = Depends(validate_agent_key)):
    return {"status": "success"}

@app.post("/api/v1/collect/packet")
async def receive_packet_log(log: PacketLog, auth: bool = Depends(validate_agent_key)):
    try:
        await packet_queue.put(log)
        return {"status": "success", "buffered": True}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/v1/collect/batch")
async def receive_batch_logs(logs: List[PacketLog], auth: bool = Depends(validate_agent_key)):
    try:
        for log in logs:
            await packet_queue.put(log)
        return {"status": "success", "count": len(logs), "buffered": True}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/stats")
async def api_stats(username: str = Depends(login_required)):
    rows = fetch_recent_traffic(limit=1200)
    protocol_counts = Counter()
    devices = {row.get("source_ip") for row in rows if row.get("source_ip")}
    recent_count = 0
    now = datetime.datetime.now(datetime.timezone.utc)
    for row in rows:
        protocol_counts[row.get("protocol") or "DNS"] += 1
        if (now - parse_timestamp(row.get("timestamp"))).total_seconds() <= 60:
            recent_count += 1
    total_mb = sum(row.get("packet_size", 0) for row in rows) / (1024*1024)
    if total_mb == 0 and rows: total_mb = len(rows) * 0.05
    return {
        "bandwidth": f"{total_mb:.2f} MB",
        "devices": len(devices),
        "vpn_alerts": len([r for r in rows if r.get("severity") == "HIGH"]),
        "protocols": dict(protocol_counts),
        "upload_speed": recent_count * 2,
        "download_speed": recent_count * 5
    }

@app.get("/api/activity")
async def api_activity(username: str = Depends(login_required)):
    rows = fetch_recent_traffic(limit=50)
    return [{
        "time": r["timestamp"], 
        "ip": r["source_ip"], 
        "dst_ip": r.get("dst_ip", "-"), 
        "domain": r["domain"], 
        "protocol": r["protocol"], 
        "size": r.get("packet_size", 0),
        "device": r.get("device_name") or "Unknown",
        "os": r.get("os_family") or "Unknown",
        "brand": r.get("brand") or "Unknown"
    } for r in rows]

@app.get("/api/devices")
async def api_devices(username: str = Depends(login_required)):
    rows = fetch_recent_traffic(limit=2000)
    devices_map = {}
    for row in rows:
        ip = row.get("source_ip")
        if ip and ip not in devices_map:
            devices_map[ip] = {
                "ip": ip, "mac": "-", "hostname": row.get("device_name") or "Unknown",
                "traffic": 0.1, "is_online": True, "last_seen": row.get("timestamp"),
                "type": row.get("device_type") or "Unknown",
                "os": row.get("os_family") or "Unknown",
                "brand": row.get("brand") or "Unknown"
            }
    return list(devices_map.values())

# --- ADMIN ENDPOINTS ---

@app.get("/api/system-health")
async def api_health():
    uptime = time.time() - START_TIME
    return {
        "status": "Operational",
        "cpu_usage": psutil.cpu_percent(),
        "ram_usage": psutil.virtual_memory().percent,
        "uptime_hours": round(uptime / 3600, 2)
    }

@app.get("/api/admin/stats")
async def admin_stats_api(username: str = Depends(admin_required)):
    return {
        "hostname": socket.gethostname(),
        "local_ip": socket.gethostbyname(socket.gethostname()),
        "cpu_percent": psutil.cpu_percent(),
        "mem_used_mb": psutil.virtual_memory().used / (1024 * 1024),
        "mem_total_mb": psutil.virtual_memory().total / (1024 * 1024),
        "maintenance_mode": MAINTENANCE_MODE
    }

@app.get("/api/admin/hotspot/status")
async def hotspot_status(username: str = Depends(admin_required)): return {"active": HOTSPOT_ACTIVE}

@app.post("/api/admin/hotspot")
async def toggle_hotspot_api(data: HotspotRequest, username: str = Depends(admin_required)):
    global HOTSPOT_ACTIVE
    HOTSPOT_ACTIVE = (data.action == 'start')
    return {"status": "success", "message": f"Hotspot {'started' if HOTSPOT_ACTIVE else 'stopped'}"}

@app.get("/api/settings/system/status")
async def system_status_api(): return {"active": MONITORING_ACTIVE}

@app.post("/api/settings/system")
async def toggle_monitoring_api(data: SystemConfigRequest, username: str = Depends(admin_required)):
    global MONITORING_ACTIVE
    MONITORING_ACTIVE = data.active
    return {"status": "success"}

@app.post("/api/settings/maintenance")
async def toggle_maintenance_api(data: SystemConfigRequest, username: str = Depends(admin_required)):
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = data.active
    return {"status": "success"}

@app.post("/api/settings/refresh")
async def trigger_refresh():
    time.sleep(0.5)
    return {"status": "success"}

@app.post("/api/admin/restart_scanner")
async def restart_scanner(username: str = Depends(admin_required)): return {"status": "success", "message": "Scanner service restarted."}

@app.post("/api/admin/reset_db")
async def reset_db_api(username: str = Depends(admin_required)):
    file = export_to_csv_task()
    success = truncate_data()
    msg = "Data reset successfully."
    if file and file != "empty": msg += f" Backup saved to {file}"
    return {"status": "success" if success else "error", "message": msg}

@app.post("/api/settings/reset")
async def reset_settings_api(username: str = Depends(admin_required)):
    return await reset_db_api(username)

# --- FRONTEND PAGES ---

@app.get("/", name="index")
async def index_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "url_for": fastapi_url_for_compat(request)})

@app.get("/dashboard", name="dashboard_page")
async def dashboard_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("dashboard.html", {"request": request, "url_for": fastapi_url_for_compat(request), "user_info": {"username": username, "role": request.session.get("role")}})

@app.get("/login", name="login_page")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "url_for": fastapi_url_for_compat(request)})

@app.post("/login")
async def login_handler(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    if not conn: return templates.TemplateResponse("login.html", {"request": request, "error": "DB Error", "url_for": fastapi_url_for_compat(request)})
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if user and verify_password(password, user["password"]):
        request.session["user_id"] = user["id"]; request.session["username"] = user["username"]; request.session["role"] = user["role"]
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid login", "url_for": fastapi_url_for_compat(request)})

@app.get("/register", name="register_page")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "url_for": fastapi_url_for_compat(request)})

@app.post("/register")
async def register_handler(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...), confirm_password: str = Form(...)):
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {"request": request, "error_message": "Passwords do not match.", "url_for": fastapi_url_for_compat(request)})
    
    conn = get_db_connection()
    if not conn: return {"status": "error"}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return templates.TemplateResponse("register.html", {"request": request, "error_message": "Username or Email already exists.", "url_for": fastapi_url_for_compat(request)})
        
        hashed = hash_password(password)
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)", (username, hashed, email, "user"))
        conn.commit()
        cursor.close(); conn.close()
        return RedirectResponse(url="/login", status_code=303)
    except Exception as e:
        print(f"Register Error: {e}")
        return templates.TemplateResponse("register.html", {"request": request, "error_message": "Registration failed.", "url_for": fastapi_url_for_compat(request)})

@app.get("/devices", name="devices_page")
async def devices_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("devices.html", {"request": request, "url_for": fastapi_url_for_compat(request), "user_info": {"username": username, "role": request.session.get("role")}})

@app.get("/activity", name="activity_page")
async def activity_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("activity.html", {"request": request, "url_for": fastapi_url_for_compat(request), "user_info": {"username": username, "role": request.session.get("role")}})

@app.get("/vpn", name="vpn_page")
async def vpn_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("vpn.html", {"request": request, "url_for": fastapi_url_for_compat(request), "user_info": {"username": username, "role": request.session.get("role")}})

@app.get("/settings", name="settings_page")
async def settings_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("settings.html", {"request": request, "url_for": fastapi_url_for_compat(request), "user_info": {"username": username, "role": request.session.get("role")}})

@app.get("/logs", name="logs_page")
async def logs_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("logs.html", {"request": request, "url_for": fastapi_url_for_compat(request), "user_info": {"username": username, "role": request.session.get("role")}})

@app.get("/export/devices/{fmt}", name="export_devices")
async def export_devices(request: Request, fmt: str, username: str = Depends(login_required)):
    filename = export_to_csv_task()
    if filename and filename != "empty":
        return FileResponse(path=filename, filename=os.path.basename(filename), media_type='text/csv')
    return RedirectResponse(url="/devices")

@app.get("/logout", name="logout_view")
async def logout_view(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")

@app.get("/maintenance", name="maintenance_page")
async def maintenance_page(request: Request):
    return templates.TemplateResponse("maintenance.html", {"request": request})

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
