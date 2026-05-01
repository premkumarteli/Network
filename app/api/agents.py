from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status, Body, Query

from ..core.config import settings
from ..core.dependencies import request_rate_limit
from ..db.session import get_db_connection
from ..services.agent_service import agent_service
from ..services.agent_auth_service import agent_auth_service, AgentAuthenticationError
from ..services.audit_service import audit_service
from ..services.device_service import device_service
from ..services.managed_device_service import managed_device_service
from ..services.metrics_service import metrics_service
from ..services.web_inspection_service import web_inspection_service
from .dpi import dpi_event_emitter
from shared.security import REENROLL_REQUEST_HEADER

import asyncio
import hmac
import logging


logger = logging.getLogger("netvisor.api.agents")
router = APIRouter()

agent_bootstrap_rate_limit = request_rate_limit(
    limit=settings.AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="agent_bootstrap",
    key_builder=lambda request: (
        f"{request.headers.get('X-Agent-Id') or (request.client.host if request.client else 'unknown')}:reenroll"
        if request.headers.get(REENROLL_REQUEST_HEADER) == "1"
        else request.headers.get("X-Agent-Id") or (request.client.host if request.client else "unknown")
    ),
)
agent_control_rate_limit = request_rate_limit(
    limit=settings.AGENT_CONTROL_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="agent_control",
    key_builder=lambda request: request.headers.get("X-Agent-Id") or (request.client.host if request.client else "unknown"),
)


def _collect_response(
    *,
    auth_context: dict | None = None,
    auth_mode: str | None = None,
    agent_id: str | None = None,
    key_version: int | None = None,
    **payload,
) -> dict:
    response = {
        "status": "success",
        "server_time": datetime.now(timezone.utc).isoformat(),
        "backend_tls_pins": agent_auth_service.transport_pins(),
    }
    effective_mode = auth_mode or str((auth_context or {}).get("auth_mode") or "").strip()
    effective_agent_id = agent_id or str((auth_context or {}).get("agent_id") or "").strip() or None
    effective_key_version = key_version if key_version is not None else (auth_context or {}).get("key_version")
    if effective_mode:
        response["agent_auth"] = {
            "mode": effective_mode,
            "agent_id": effective_agent_id,
            "key_version": effective_key_version,
        }
    response.update(payload)
    return response


async def validate_agent_bootstrap_key(request: Request):
    key = str(request.headers.get("X-API-Key") or "")
    if not hmac.compare_digest(key, settings.AGENT_API_KEY):
        metrics_service.increment("agent_bootstrap_auth_failures_total")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Agent Key")
    metrics_service.increment("agent_bootstrap_auth_success_total")
    return True


async def validate_agent_key(request: Request):
    conn = get_db_connection()
    try:
        body = await request.body()
        context = agent_auth_service.authenticate_request(conn, request, body)
        conn.commit()
        return context
    except AgentAuthenticationError as exc:
        conn.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    finally:
        conn.close()


def _require_authenticated_agent_id(auth_context: dict, claimed_agent_id: str | None, *, source: str) -> str:
    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    claimed = str(claimed_agent_id or "").strip()
    if not claimed:
        raise HTTPException(status_code=400, detail=f"agent_id is required in {source}")

    if authenticated_agent_id != claimed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent ID mismatch: authenticated agent ID does not match {source} agent ID",
        )

    return authenticated_agent_id


def _require_signed_agent_auth(auth_context: dict) -> None:
    if str(auth_context.get("auth_mode") or "") != "signed":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signed agent authentication is required for this operation.",
        )


def _resolve_org_id(cursor, requested_org_id: str | None) -> str | None:
    if requested_org_id and not settings.SINGLE_ORG_MODE:
        return requested_org_id

    cursor.execute("SELECT id FROM organizations LIMIT 1")
    org_row = cursor.fetchone()
    if org_row:
        return org_row["id"]

    return requested_org_id or settings.DEFAULT_ORGANIZATION_ID


def _lookup_agent_organization_id(cursor, agent_id: str) -> str | None:
    cursor.execute(
        """
        SELECT organization_id
        FROM agents
        WHERE id = %s
        LIMIT 1
        """,
        (agent_id,),
    )
    row = cursor.fetchone()
    return row["organization_id"] if row else None


@router.post("/register")
async def register_agent(
    reg: dict,
    _rate_limited: bool = Depends(agent_bootstrap_rate_limit),
    authorized: bool = Depends(validate_agent_bootstrap_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        metrics_service.increment("agent_registration_attempts_total")
        agent_id = str(reg.get("agent_id") or "").strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required")

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, reg.get("organization_id"))
        cursor.close()
        cursor = None

        logger.info("Registering agent %s for org %s", agent_id, org_id)

        existing_credential = agent_auth_service.get_active_credential(conn, agent_id=agent_id)
        force_reenroll = bool(reg.get("reenroll"))

        agent_service.upsert_agent(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            api_key=None,
            hostname=reg.get("hostname"),
            ip_address=reg.get("device_ip"),
            os_family=reg.get("os"),
            version=reg.get("version"),
            inspection_state=reg.get("web_inspection"),
            cpu_usage=float(reg.get("cpu_usage") or 0.0),
            ram_usage=float(reg.get("ram_usage") or 0.0),
        )

        managed_device_service.upsert_device(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            device_ip=reg.get("device_ip"),
            device_mac=reg.get("device_mac"),
            hostname=reg.get("hostname"),
            os_family=reg.get("os"),
        )
        device_service.touch_device_seen(
            conn,
            ip=reg.get("device_ip"),
            organization_id=org_id,
            seen_at=reg.get("time"),
            agent_id=agent_id,
            hostname=reg.get("hostname"),
            mac=reg.get("device_mac"),
            vendor="Managed Agent",
            device_type="Managed Device",
            os_family=reg.get("os"),
            create_if_missing=True,
        )

        credential = None
        if existing_credential and force_reenroll:
            credential = agent_auth_service.rotate_credential(conn, agent_id=agent_id)
            metrics_service.increment("agent_registration_reenrollments_total")
        elif not existing_credential:
            credential = agent_auth_service.issue_initial_credential(conn, agent_id=agent_id)
            metrics_service.increment("agent_registration_initial_enrollments_total")
        else:
            metrics_service.increment("agent_registration_reregistrations_total")

        conn.commit()

        audit_service.log_agent_registration(
            organization_id=str(org_id),
            username="system",
            agent_id=agent_id,
            action="agent_registration_via_bootstrap",
            details="first_time" if credential else "re_registration",
        )

        response = _collect_response(
            auth_mode="bootstrap",
            agent_id=agent_id,
            organization_id=org_id,
        )
        if credential:
            response["agent_credentials"] = credential.as_response()
        else:
            response["agent_credentials"] = None
            response["message"] = "Agent already registered. Use explicit rotation endpoint for credential updates."
        return response
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/heartbeat")
async def agent_heartbeat(
    hb: dict,
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        agent_id = _require_authenticated_agent_id(auth_context, hb.get("agent_id"), source="request payload")

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, hb.get("organization_id"))
        cursor.close()
        cursor = None

        agent_service.upsert_agent(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            api_key=None,
            hostname=hb.get("hostname"),
            ip_address=hb.get("device_ip"),
            os_family=hb.get("os"),
            version=hb.get("version"),
            inspection_state=hb.get("web_inspection"),
            cpu_usage=float(hb.get("cpu_usage") or 0.0),
            ram_usage=float(hb.get("ram_usage") or 0.0),
        )

        managed_device_service.upsert_device(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            device_ip=hb.get("device_ip"),
            device_mac=hb.get("device_mac"),
            hostname=hb.get("hostname"),
            os_family=hb.get("os"),
        )
        device_service.touch_device_seen(
            conn,
            ip=hb.get("device_ip"),
            organization_id=org_id,
            seen_at=hb.get("time"),
            agent_id=agent_id,
            hostname=hb.get("hostname"),
            mac=hb.get("device_mac"),
            vendor="Managed Agent",
            device_type="Managed Device",
            os_family=hb.get("os"),
            create_if_missing=True,
        )
        conn.commit()
        return _collect_response(
            auth_context=auth_context,
            organization_id=org_id,
        )
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.get("/web-policy")
async def get_web_policy(
    agent_id: str = Query(...),
    device_ip: str = Query(...),
    organization_id: str | None = Query(default=None),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        authenticated_agent_id = _require_authenticated_agent_id(
            auth_context,
            agent_id,
            source="query parameter",
        )

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, organization_id)
        cursor.close()
        cursor = None

        policy = web_inspection_service.get_policy(
            conn,
            agent_id=authenticated_agent_id,
            device_ip=device_ip,
            organization_id=org_id,
        )
        return _collect_response(auth_context=auth_context, **policy)
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/web-events/batch")
async def receive_web_events(
    events: list = Body(...),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    if not events:
        return _collect_response(auth_context=auth_context, count=0)

    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    for index, event in enumerate(events):
        _require_authenticated_agent_id(
            auth_context,
            event.get("agent_id"),
            source=f"event at index {index}",
        )

    conn = get_db_connection()
    try:
        count = web_inspection_service.store_events(conn, events)
        loop = asyncio.get_event_loop()
        for event in events:
            if "timestamp" not in event:
                from datetime import datetime, timezone

                event["timestamp"] = datetime.now(timezone.utc).isoformat()
            if "app" not in event:
                event["app"] = event.get("browser_name") or event.get("process_name") or "Unknown"

            event["agent_id"] = authenticated_agent_id
            loop.create_task(dpi_event_emitter.emit(event))
        return _collect_response(auth_context=auth_context, count=count)
    except Exception as exc:
        logger.error("Failed to store web inspection events: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to store web events")
    finally:
        conn.close()


@router.post("/rotate-credential")
async def rotate_agent_credential(
    authorization: dict = Body(...),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    """Explicitly rotate agent credential - returns new credential only when called."""
    _require_signed_agent_auth(auth_context)

    conn = get_db_connection()
    cursor = None
    try:
        agent_id = _require_authenticated_agent_id(auth_context, authorization.get("agent_id"), source="request body")

        cursor = conn.cursor(dictionary=True)
        org_id = _lookup_agent_organization_id(cursor, agent_id) or settings.DEFAULT_ORGANIZATION_ID or "default-org-id"
        cursor.close()
        cursor = None

        credential = agent_auth_service.rotate_credential(conn, agent_id=agent_id)
        conn.commit()

        audit_service.log_credential_rotation(
            organization_id=str(org_id),
            username="system",
            agent_id=agent_id,
        )

        return _collect_response(
            auth_context=auth_context,
            agent_credentials=credential.as_response(),
            message="Credential rotated successfully. Previous credential is now invalid.",
        )
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        logger.error("Failed to rotate agent credential: %s", exc, exc_info=True)
        conn.rollback()
        raise HTTPException(status_code=500, detail="Failed to rotate credential")
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/devices/batch")
async def receive_devices(
    devices: list = Body(...),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    """Receive ARP-discovered devices from an agent and upsert them into the devices table."""
    if not devices:
        return _collect_response(auth_context=auth_context, count=0)

    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    for index, dev in enumerate(devices):
        _require_authenticated_agent_id(
            auth_context,
            dev.get("agent_id"),
            source=f"device at index {index}",
        )

    conn = get_db_connection()
    cursor = None
    try:
        from ..main import p_sio

        cursor = conn.cursor(dictionary=True)
        requested_org_id = None
        if devices and isinstance(devices[0], dict):
            requested_org_id = devices[0].get("organization_id")
        org_id = _resolve_org_id(cursor, requested_org_id)
        cursor.close()
        cursor = None

        count = 0
        for dev in devices:
            logger.debug("Upserting device: %s for org %s", dev.get("ip"), dev.get("organization_id"))
            if device_service.touch_device_seen(
                conn,
                ip=dev.get("ip"),
                organization_id=org_id,
                seen_at=dev.get("last_seen"),
                agent_id=authenticated_agent_id,
                hostname=dev.get("hostname"),
                mac=dev.get("mac"),
                vendor=dev.get("vendor"),
                device_type=dev.get("device_type"),
                os_family=dev.get("os_family"),
                create_if_missing=True,
            ):
                count += 1
            await p_sio.emit("device_event", {"data": dev})

        conn.commit()
        logger.info("Upserted %s device(s) from agent scan.", count)
        return _collect_response(auth_context=auth_context, count=count)
    except Exception as exc:
        logger.error("Failed to upsert devices: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to store devices")
    finally:
        if cursor:
            cursor.close()
        conn.close()
