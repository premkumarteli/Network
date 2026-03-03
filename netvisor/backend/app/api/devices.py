from fastapi import APIRouter, Depends
from typing import List
from ..core.dependencies import get_current_user
from ..db.session import get_db_connection
from ..schemas.device_schema import Device
from ..services.device_service import device_service

router = APIRouter()

@router.get("/", response_model=List[Device])
async def list_devices(
    current_user: dict = Depends(get_current_user)
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        devices = device_service.get_devices(conn, organization_id=org_id)
        # Transform/Format if necessary
        for d in devices:
            if d.get("last_seen") and hasattr(d["last_seen"], "strftime"):
                d["last_seen"] = d["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            d["id"] = d["ip"] # Using IP as ID for now
            d["is_online"] = True # Simplified
            d["device_type"] = "Unknown"
            d["os_family"] = "Unknown"
            d["brand"] = "Unknown"
            d["organization_id"] = org_id
        return devices
    finally:
        conn.close()
