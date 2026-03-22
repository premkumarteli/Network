from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import List

from ..core.config import settings
from ..db.session import get_db_connection
from ..schemas.flow_schema import FlowBase
from ..schemas.user_schema import GenericResponse
from ..services.flow_service import flow_service
from ..services.gateway_service import gateway_service

router = APIRouter()


async def validate_gateway_key(request: Request):
    key = request.headers.get("X-Gateway-Key") or request.headers.get("X-API-Key")
    if key != settings.GATEWAY_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Gateway Key")
    return True


@router.post("/register", response_model=GenericResponse)
async def register_gateway(reg: dict, authorized: bool = Depends(validate_gateway_key)):
    conn = get_db_connection()
    try:
        gateway_service.upsert_gateway(
            conn,
            gateway_id=reg.get("gateway_id", ""),
            hostname=reg.get("hostname"),
            capture_mode=reg.get("capture_mode"),
        )
        return {"status": "success", "message": "Gateway registered"}
    finally:
        conn.close()


@router.post("/heartbeat", response_model=GenericResponse)
async def gateway_heartbeat(hb: dict, authorized: bool = Depends(validate_gateway_key)):
    conn = get_db_connection()
    try:
        gateway_service.upsert_gateway(
            conn,
            gateway_id=hb.get("gateway_id", ""),
            hostname=hb.get("hostname"),
            capture_mode=hb.get("capture_mode"),
        )
        return {"status": "success", "message": "Gateway heartbeat recorded"}
    finally:
        conn.close()


@router.post("/flows/batch", response_model=GenericResponse)
async def ingest_gateway_batch(
    flows: List[FlowBase],
    authorized: bool = Depends(validate_gateway_key)
):
    count = 0
    for flow in flows:
        gateway_flow = flow.model_copy(update={"source_type": "gateway", "metadata_only": True})
        if await flow_service.buffer_flow(gateway_flow):
            count += 1

    return {"status": "success", "message": f"Buffered {count}/{len(flows)} gateway flows"}
