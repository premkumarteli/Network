from fastapi import APIRouter, Depends, File, HTTPException, status
from fastapi.responses import FileResponse
from typing import List, Optional
import psutil
import time
import socket
import os
import logging

from ..dependencies import login_required, admin_required
from ..services.data_service import get_stats, fetch_recent_traffic, export_to_csv_task, truncate_data, fetch_system_logs, fetch_vpn_alerts
from core.models import (
    HotspotRequest, SystemConfigRequest, GenericResponse, 
    DeviceResponse, SystemHealthResponse, AdminStatsResponse, 
    ActivityEntry, LogsResponse
)
from core.state import state

logger = logging.getLogger("netvisor.api")
router = APIRouter(tags=["System API"])


@router.get("/logs", response_model=LogsResponse)
async def api_logs():
    admin_logs = fetch_system_logs(limit=20)
    vpn_logs = fetch_vpn_alerts(limit=20)
    
    return {
        "admin": [{
            "time": l["timestamp"],
            "action": l["action"],
            "details": f"User: {l['username']} | IP: {l['ip_address']}"
        } for l in admin_logs],
        "vpn": [{
            "time": l["timestamp"],
            "src_ip": l["source_ip"],
            "score": (l["risk_score"] or 0) / 100.0,
            "reason": f"High Risk Traffic ({l['protocol']})"
        } for l in vpn_logs]
    }

@router.get("/system-health", response_model=SystemHealthResponse)
async def api_health():
    uptime = time.time() - state.start_time
    return {
        "status": "Operational",
        "cpu_usage": psutil.cpu_percent(),
        "ram_usage": psutil.virtual_memory().percent,
        "uptime_hours": round(uptime / 3600, 2)
    }

@router.get("/admin/stats", response_model=AdminStatsResponse)
async def admin_stats_api(username: str = Depends(login_required)):
    return {
        "hostname": socket.gethostname(),
        "local_ip": socket.gethostbyname(socket.gethostname()),
        "cpu_percent": psutil.cpu_percent(),
        "mem_used_mb": psutil.virtual_memory().used / (1024 * 1024),
        "mem_total_mb": psutil.virtual_memory().total / (1024 * 1024),
        "maintenance_mode": state.maintenance_mode
    }

@router.get("/stats")
async def api_stats():
    # Statistics aggregator - returns dynamic dict based on service
    return get_stats()

@router.get("/activity", response_model=List[ActivityEntry])
async def api_activity(severity: Optional[str] = None):
    rows = fetch_recent_traffic(limit=50, severity=severity)
    return [{
        "time": r["timestamp"], 
        "src_ip": r["source_ip"], 
        "dst_ip": r.get("dst_ip", "-"), 
        "domain": r["domain"], 
        "protocol": r["protocol"], 
        "size": r.get("packet_size", 0),
        "device": r.get("device_name") or "Unknown",
        "os": r.get("os_family") or "Unknown",
        "brand": r.get("brand") or "Unknown",
        "mac": r.get("mac_address", "-"),
        "confidence": r.get("identity_confidence", "low"),
        "severity": r.get("severity", "LOW")
    } for r in rows]

@router.get("/devices", response_model=List[DeviceResponse])
async def api_devices(username: str = Depends(login_required)):
    from ..services.data_service import fetch_device_risks
    
    traffic_rows = fetch_recent_traffic(limit=2000)
    risk_rows = fetch_device_risks()
    
    risks_map = {r['device_id']: r for r in risk_rows}
    
    devices_map = {}
    for row in traffic_rows:
        ip = row.get("source_ip")
        mac = row.get("mac_address", "-")
        if ip and ip not in devices_map:
            # Get risk for this device (by MAC preferred)
            risk = risks_map.get(mac, {})
            
            devices_map[ip] = {
                "ip": ip, "mac": mac, "hostname": row.get("device_name") or "Unknown",
                "traffic": 0.1, "is_online": True, "last_seen": row.get("timestamp"),
                "type": row.get("device_type") or "Unknown",
                "os": row.get("os_family") or "Unknown",
                "brand": row.get("brand") or "Unknown",
                "confidence": row.get("identity_confidence", "low"),
                "risk_score": int(risk.get("current_score", 0)),
                "risk_level": risk.get("risk_level", "LOW")
            }
    return list(devices_map.values())

@router.get("/admin/hotspot/status")
async def hotspot_status(username: str = Depends(login_required)): 
    return {"active": state.hotspot_active}

@router.post("/admin/hotspot", response_model=GenericResponse)
async def toggle_hotspot_api(data: HotspotRequest, username: str = Depends(admin_required)):
    state.hotspot_active = (data.action == 'start')
    return {"status": "success", "message": f"Hotspot {'started' if state.hotspot_active else 'stopped'}"}

@router.get("/settings/system/status")
async def system_status_api(username: str = Depends(login_required)): 
    return {"active": state.monitoring_active}

@router.post("/settings/system", response_model=GenericResponse)
async def toggle_monitoring_api(data: SystemConfigRequest, username: str = Depends(admin_required)):
    state.monitoring_active = data.active
    return {"status": "success", "message": "Monitoring state updated"}

@router.post("/settings/maintenance", response_model=GenericResponse)
async def toggle_maintenance_api(data: SystemConfigRequest, username: str = Depends(admin_required)):
    state.maintenance_mode = data.active
    return {"status": "success", "message": f"Maintenance mode {'enabled' if data.active else 'disabled'}"}

@router.post("/admin/reset_db", response_model=GenericResponse)
async def reset_db_api(username: str = Depends(admin_required)):
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
    return JSONResponse(status_code=404, content={"status": "error", "message": "No data to export"})
