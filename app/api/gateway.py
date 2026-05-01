from __future__ import annotations

from datetime import datetime, timezone
import hmac
import logging
from typing import List

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from ..core.config import settings
from ..core.dependencies import request_rate_limit
from ..db.session import get_db_connection
from ..schemas.flow_schema import FlowBase
from ..schemas.user_schema import GenericResponse
from ..services.flow_service import FlowQueueBackpressureError, flow_service
from ..services.gateway_auth_service import GatewayAuthenticationError, gateway_auth_service
from ..services.gateway_service import gateway_service
from ..services.metrics_service import metrics_service
from shared.security import REENROLL_REQUEST_HEADER

logger = logging.getLogger("netvisor.api.gateway")
router = APIRouter()

gateway_bootstrap_rate_limit = request_rate_limit(
    limit=settings.AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="gateway_bootstrap",
    key_builder=lambda request: (
        f"{request.headers.get('X-Gateway-Id') or (request.client.host if request.client else 'unknown')}:reenroll"
        if request.headers.get(REENROLL_REQUEST_HEADER) == "1"
        else request.headers.get("X-Gateway-Id") or (request.client.host if request.client else "unknown")
    ),
)
gateway_control_rate_limit = request_rate_limit(
    limit=settings.AGENT_CONTROL_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="gateway_control",
    key_builder=lambda request: request.headers.get("X-Gateway-Id") or (request.client.host if request.client else "unknown"),
)
gateway_flow_rate_limit = request_rate_limit(
    limit=settings.AGENT_FLOW_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="gateway_flow",
    key_builder=lambda request: request.headers.get("X-Gateway-Id") or (request.client.host if request.client else "unknown"),
)


def _collect_response(
    *,
    auth_context: dict | None = None,
    auth_mode: str | None = None,
    gateway_id: str | None = None,
    key_version: int | None = None,
    **payload,
) -> dict:
    response = {
        "status": "success",
        "server_time": datetime.now(timezone.utc).isoformat(),
        "backend_tls_pins": gateway_auth_service.transport_pins(),
    }
    effective_mode = auth_mode or str((auth_context or {}).get("auth_mode") or "").strip()
    effective_gateway_id = gateway_id or str((auth_context or {}).get("gateway_id") or "").strip() or None
    effective_key_version = key_version if key_version is not None else (auth_context or {}).get("key_version")
    if effective_mode:
        response["gateway_auth"] = {
            "mode": effective_mode,
            "gateway_id": effective_gateway_id,
            "key_version": effective_key_version,
        }
    response.update(payload)
    return response


async def validate_gateway_bootstrap_key(request: Request):
    key = str(request.headers.get("X-Gateway-Key") or "")
    if not hmac.compare_digest(key, settings.GATEWAY_API_KEY):
        metrics_service.increment("gateway_bootstrap_auth_failures_total")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized gateway bootstrap key")
    metrics_service.increment("gateway_bootstrap_auth_success_total")
    return True


async def validate_gateway_request(request: Request):
    conn = get_db_connection()
    try:
        body = await request.body()
        context = gateway_auth_service.authenticate_request(conn, request, body)
        conn.commit()
        return context
    except GatewayAuthenticationError as exc:
        conn.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    finally:
        conn.close()


def _require_authenticated_gateway_id(auth_context: dict, claimed_gateway_id: str | None, *, source: str) -> str:
    authenticated_gateway_id = str(auth_context.get("gateway_id") or "").strip()
    if not authenticated_gateway_id:
        raise HTTPException(status_code=400, detail="gateway_id is required in authentication")

    claimed = str(claimed_gateway_id or "").strip()
    if not claimed:
        raise HTTPException(status_code=400, detail=f"gateway_id is required in {source}")

    if authenticated_gateway_id != claimed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Gateway ID mismatch: authenticated gateway ID does not match {source} gateway ID",
        )

    return authenticated_gateway_id


def _require_signed_gateway_auth(auth_context: dict) -> None:
    if str(auth_context.get("auth_mode") or "") != "signed":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signed gateway authentication is required for this operation.",
        )


def _resolve_org_id(cursor, requested_org_id: str | None) -> str | None:
    if requested_org_id and not settings.SINGLE_ORG_MODE:
        return requested_org_id

    cursor.execute("SELECT id FROM organizations LIMIT 1")
    org_row = cursor.fetchone()
    if org_row:
        return org_row["id"]

    return requested_org_id or settings.DEFAULT_ORGANIZATION_ID


def _lookup_gateway_organization_id(cursor, gateway_id: str) -> str | None:
    cursor.execute(
        """
        SELECT organization_id
        FROM gateways
        WHERE gateway_id = %s
        LIMIT 1
        """,
        (gateway_id,),
    )
    row = cursor.fetchone()
    return row["organization_id"] if row else None


@router.post("/register", response_model=GenericResponse)
async def register_gateway(
    reg: dict,
    _rate_limited: bool = Depends(gateway_bootstrap_rate_limit),
    authorized: bool = Depends(validate_gateway_bootstrap_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        metrics_service.increment("gateway_registration_attempts_total")
        gateway_id = str(reg.get("gateway_id") or "").strip()
        if not gateway_id:
            raise HTTPException(status_code=400, detail="gateway_id is required")

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, reg.get("organization_id"))
        cursor.close()
        cursor = None

        existing_credential = gateway_auth_service.get_active_credential(conn, gateway_id=gateway_id)
        force_reenroll = bool(reg.get("reenroll"))
        gateway_service.upsert_gateway(
            conn,
            gateway_id=gateway_id,
            organization_id=org_id,
            hostname=reg.get("hostname"),
            capture_mode=reg.get("capture_mode"),
        )

        credential = None
        if existing_credential and force_reenroll:
            credential = gateway_auth_service.rotate_credential(conn, gateway_id=gateway_id)
            metrics_service.increment("gateway_registration_reenrollments_total")
        elif not existing_credential:
            credential = gateway_auth_service.issue_initial_credential(conn, gateway_id=gateway_id)
            metrics_service.increment("gateway_registration_initial_enrollments_total")
        else:
            metrics_service.increment("gateway_registration_reregistrations_total")

        conn.commit()

        response = _collect_response(
            auth_mode="bootstrap",
            gateway_id=gateway_id,
            organization_id=org_id,
        )
        if credential:
            response["gateway_credentials"] = credential.as_response()
            if force_reenroll:
                response["message"] = "Gateway re-enrolled successfully. Previous credential is now invalid."
            else:
                response["message"] = "Gateway registered and enrolled successfully."
        else:
            response["gateway_credentials"] = None
            response["message"] = "Gateway already registered. Use the rotation endpoint to issue a new credential."
        return response
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/heartbeat", response_model=GenericResponse)
async def gateway_heartbeat(
    hb: dict,
    _rate_limited: bool = Depends(gateway_control_rate_limit),
    auth_context: dict = Depends(validate_gateway_request),
):
    conn = get_db_connection()
    cursor = None
    try:
        gateway_id = _require_authenticated_gateway_id(auth_context, hb.get("gateway_id"), source="request payload")

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(
            cursor,
            hb.get("organization_id") or _lookup_gateway_organization_id(cursor, gateway_id),
        )
        cursor.close()
        cursor = None

        gateway_service.upsert_gateway(
            conn,
            gateway_id=gateway_id,
            organization_id=org_id,
            hostname=hb.get("hostname"),
            capture_mode=hb.get("capture_mode"),
        )
        conn.commit()
        return _collect_response(
            auth_context=auth_context,
            organization_id=org_id,
            message="Gateway heartbeat recorded.",
        )
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/flows/batch", response_model=GenericResponse)
async def ingest_gateway_batch(
    flows: List[FlowBase],
    _rate_limited: bool = Depends(gateway_flow_rate_limit),
    auth_context: dict = Depends(validate_gateway_request),
):
    if not flows:
        return _collect_response(auth_context=auth_context, count=0)

    authenticated_gateway_id = str(auth_context.get("gateway_id") or "").strip()
    if not authenticated_gateway_id:
        raise HTTPException(status_code=400, detail="gateway_id is required in authentication")

    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        requested_org_id = str(getattr(flows[0], "organization_id", "") or "").strip() or None
        org_id = _resolve_org_id(
            cursor,
            requested_org_id or _lookup_gateway_organization_id(cursor, authenticated_gateway_id),
        )
        cursor.close()
        cursor = None
    finally:
        if cursor:
            cursor.close()
        conn.close()

    gateway_flows: list[FlowBase] = []
    for index, flow in enumerate(flows):
        _require_authenticated_gateway_id(
            auth_context,
            flow.agent_id,
            source=f"flow at index {index}",
        )
        gateway_flow = flow.model_copy(
            update={
                "agent_id": authenticated_gateway_id,
                "organization_id": org_id or flow.organization_id,
                "source_type": "gateway",
                "metadata_only": True,
            }
        )
        gateway_flows.append(gateway_flow)

    try:
        success = await flow_service.buffer_flows(gateway_flows)
    except FlowQueueBackpressureError as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    count = len(gateway_flows) if success else 0

    return _collect_response(
        auth_context=auth_context,
        organization_id=org_id,
        message=f"Queued {count}/{len(flows)} gateway flows",
    )


@router.post("/rotate-credential", response_model=GenericResponse)
async def rotate_gateway_credential(
    authorization: dict = Body(...),
    _rate_limited: bool = Depends(gateway_control_rate_limit),
    auth_context: dict = Depends(validate_gateway_request),
):
    _require_signed_gateway_auth(auth_context)

    conn = get_db_connection()
    cursor = None
    try:
        gateway_id = _require_authenticated_gateway_id(auth_context, authorization.get("gateway_id"), source="request body")

        cursor = conn.cursor(dictionary=True)
        org_id = _lookup_gateway_organization_id(cursor, gateway_id) or settings.DEFAULT_ORGANIZATION_ID or "default-org-id"
        cursor.close()
        cursor = None

        credential = gateway_auth_service.rotate_credential(conn, gateway_id=gateway_id)
        conn.commit()

        return _collect_response(
            auth_context=auth_context,
            organization_id=org_id,
            gateway_credentials=credential.as_response(),
            message="Gateway credential rotated successfully. Previous credential is now invalid.",
        )
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        logger.error("Failed to rotate gateway credential: %s", exc, exc_info=True)
        conn.rollback()
        raise HTTPException(status_code=500, detail="Failed to rotate gateway credential")
    finally:
        if cursor:
            cursor.close()
        conn.close()
