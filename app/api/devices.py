from fastapi import APIRouter, Depends
from typing import List
from ..core.dependencies import get_current_user, require_org_admin
from ..db.session import get_db_connection
from ..schemas.device_schema import Device
from ..services.device_service import device_service

router = APIRouter()


@router.get("/", response_model=List[Device])
async def list_devices(
    current_user: dict = Depends(require_org_admin)
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        devices = device_service.get_devices(conn, organization_id=org_id)

        # For flow_logs fallback rows that lack an 'id' field
        for d in devices:
            if "id" not in d or d["id"] is None:
                d["id"] = d["ip"]

        return devices
    finally:
        conn.close()


@router.get("/{device_id}/risk")
async def get_device_risk(
    device_id: str,
    current_user: dict = Depends(require_org_admin)
):
    conn = get_db_connection()
    try:
        risk = device_service.get_device_risk(conn, device_id)
        if not risk:
            return {"device_id": device_id, "current_score": 0, "risk_level": "LOW", "reasons": []}
        return risk
    finally:
        conn.close()
