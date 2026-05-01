from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List
from ..core.config import settings
from ..core.dependencies import request_rate_limit
from ..schemas.flow_schema import FlowBase
from ..schemas.user_schema import GenericResponse
from ..services.flow_service import FlowQueueBackpressureError, flow_service
from .agents import validate_agent_key, _require_authenticated_agent_id, _collect_response
import logging

logger = logging.getLogger("netvisor.api.flows")
router = APIRouter()

agent_flow_rate_limit = request_rate_limit(
    limit=settings.AGENT_FLOW_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="agent_flow_ingest",
    key_builder=lambda request: request.headers.get("X-Agent-Id") or (request.client.host if request.client else "unknown"),
)

@router.post("/ingest", response_model=GenericResponse)
async def ingest_flow(
    flow: FlowBase,
    _rate_limited: bool = Depends(agent_flow_rate_limit),
    auth_context: dict = Depends(validate_agent_key)
):
    _require_authenticated_agent_id(auth_context, flow.agent_id, source="flow payload")
    try:
        success = await flow_service.buffer_flow(flow)
    except FlowQueueBackpressureError as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    if not success:
        raise HTTPException(status_code=503, detail="Unable to queue flow batch")
    return _collect_response(
        auth_context=auth_context,
        message="Flow queued",
        flow_metrics=flow_service.metrics_snapshot(),
    )

@router.post("/batch", response_model=GenericResponse)
async def ingest_batch(
    flows: List[FlowBase],
    _rate_limited: bool = Depends(agent_flow_rate_limit),
    auth_context: dict = Depends(validate_agent_key)
):
    for f in flows:
        _require_authenticated_agent_id(auth_context, f.agent_id, source="flow payload")
    try:
        success = await flow_service.buffer_flows(flows)
    except FlowQueueBackpressureError as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    count = len(flows) if success else 0
    return _collect_response(
        auth_context=auth_context,
        message=f"Queued {count}/{len(flows)} flows",
        count=count,
        requested=len(flows),
        flow_metrics=flow_service.metrics_snapshot(),
    )
