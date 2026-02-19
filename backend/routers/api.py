from fastapi import APIRouter, Depends, File
from fastapi.responses import FileResponse
import psutil
import time
import socket
import os
from ..dependencies import login_required
from ..services.data_service import get_stats, fetch_recent_traffic, export_to_csv_task, truncate_data
from core.models import HotspotRequest, SystemConfigRequest

router = APIRouter()

# Default State (moved to dynamic or remained in memory)
START_TIME = time.time()
MAINTENANCE_MODE = False
MONITORING_ACTIVE = True
HOTSPOT_ACTIVE = False

@router.get("/system-health")
async def api_health():
    uptime = time.time() - START_TIME
    return {
        "status": "Operational",
        "cpu_usage": psutil.cpu_percent(),
        "ram_usage": psutil.virtual_memory().percent,
        "uptime_hours": round(uptime / 3600, 2)
    }

@router.get("/admin/stats")
async def admin_stats_api(username: str = Depends(login_required)):
    return {
        "hostname": socket.gethostname(),
        "local_ip": socket.gethostbyname(socket.gethostname()),
        "cpu_percent": psutil.cpu_percent(),
        "mem_used_mb": psutil.virtual_memory().used / (1024 * 1024),
        "mem_total_mb": psutil.virtual_memory().total / (1024 * 1024),
        "maintenance_mode": MAINTENANCE_MODE
    }

@router.get("/stats")
async def api_stats(username: str = Depends(login_required)):
    return get_stats()

@router.get("/activity")
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
        "brand": r.get("brand") or "Unknown",
        "mac": r.get("mac_address", "-"),
        "confidence": r.get("identity_confidence", "low")
    } for r in rows]

@router.get("/devices")
async def api_devices(username: str = Depends(login_required)):
    rows = fetch_recent_traffic(limit=2000)
    devices_map = {}
    for row in rows:
        ip = row.get("source_ip")
        if ip and ip not in devices_map:
            devices_map[ip] = {
                "ip": ip, "mac": row.get("mac_address", "-"), "hostname": row.get("device_name") or "Unknown",
                "traffic": 0.1, "is_online": True, "last_seen": row.get("timestamp"),
                "type": row.get("device_type") or "Unknown",
                "os": row.get("os_family") or "Unknown",
                "brand": row.get("brand") or "Unknown",
                "confidence": row.get("identity_confidence", "low")
            }
    return list(devices_map.values())

@router.get("/admin/hotspot/status")
async def hotspot_status(): return {"active": HOTSPOT_ACTIVE}

@router.post("/admin/hotspot")
async def toggle_hotspot_api(data: HotspotRequest):
    global HOTSPOT_ACTIVE
    HOTSPOT_ACTIVE = (data.action == 'start')
    return {"status": "success", "message": f"Hotspot {'started' if HOTSPOT_ACTIVE else 'stopped'}"}

@router.get("/settings/system/status")
async def system_status_api(): return {"active": MONITORING_ACTIVE}

@router.post("/settings/system")
async def toggle_monitoring_api(data: SystemConfigRequest):
    global MONITORING_ACTIVE
    MONITORING_ACTIVE = data.active
    return {"status": "success"}

@router.post("/settings/maintenance")
async def toggle_maintenance_api(data: SystemConfigRequest):
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = data.active
    return {"status": "success"}

@router.post("/admin/reset_db")
async def reset_db_api(username: str = Depends(login_required)):
    file = export_to_csv_task()
    success = truncate_data()
    msg = "Data reset successfully."
    if file and file != "empty": msg += f" Backup saved to {file}"
    return {"status": "success" if success else "error", "message": msg}

@router.get("/export/devices/{fmt}", name="export_devices")
async def api_export_devices(fmt: str, username: str = Depends(login_required)):
    filename = export_to_csv_task()
    if filename and filename != "empty":
        return FileResponse(path=filename, filename=os.path.basename(filename), media_type='text/csv')
    return {"status": "error", "message": "No data to export"}
