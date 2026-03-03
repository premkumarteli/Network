from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List
from ..core.config import settings
from ..schemas.flow_schema import FlowBase
from ..schemas.user_schema import GenericResponse
from ..services.flow_service import flow_service
import logging

logger = logging.getLogger("netvisor.api.flows")
router = APIRouter()

async def validate_agent_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != settings.AGENT_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Agent Key")
    return True

@router.post("/ingest", response_model=GenericResponse)
async def ingest_flow(
    flow: FlowBase,
    authorized: bool = Depends(validate_agent_key)
):
    success = await flow_service.buffer_flow(flow)
    if not success:
        raise HTTPException(status_code=503, detail="Buffer full")
    return {"status": "success", "message": "Flow buffered"}

@router.post("/batch", response_model=GenericResponse)
async def ingest_batch(
    flows: List[FlowBase],
    authorized: bool = Depends(validate_agent_key)
):
    count = 0
    for f in flows:
        if await flow_service.buffer_flow(f):
            count += 1
    return {"status": "success", "message": f"Buffered {count}/{len(flows)} flows"}
