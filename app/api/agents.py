from fastapi import APIRouter, Depends, HTTPException, Request, status, Body, Query
from ..core.config import settings
from ..db.session import get_db_connection
from ..services.agent_service import agent_service
from ..services.device_service import device_service
from ..services.managed_device_service import managed_device_service
from ..services.web_inspection_service import web_inspection_service
import logging

logger = logging.getLogger("netvisor.api.agents")
router = APIRouter()


async def validate_agent_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != settings.AGENT_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Agent Key")
    return True


def _resolve_org_id(cursor, requested_org_id: str | None) -> str | None:
    if requested_org_id and not settings.SINGLE_ORG_MODE:
        return requested_org_id

    cursor.execute("SELECT id FROM organizations LIMIT 1")
    org_row = cursor.fetchone()
    if org_row:
        return org_row["id"]

    return requested_org_id or settings.DEFAULT_ORGANIZATION_ID


@router.post("/register")
async def register_agent(reg: dict, authorized: bool = Depends(validate_agent_key)):
    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, reg.get("organization_id"))
        cursor.close()
        cursor = None
        logger.info(f"Registering agent {reg.get('agent_id')} for org {org_id}")

        agent_service.upsert_agent(
            conn,
            agent_id=reg.get("agent_id", ""),
            organization_id=org_id,
            api_key=settings.AGENT_API_KEY,
            hostname=reg.get("hostname"),
            ip_address=reg.get("device_ip"),
            os_family=reg.get("os"),
            version=reg.get("version"),
            inspection_state=reg.get("web_inspection"),
        )

        managed_device_service.upsert_device(
            conn,
            agent_id=reg.get("agent_id", ""),
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
            agent_id=reg.get("agent_id"),
            hostname=reg.get("hostname"),
            mac=reg.get("device_mac"),
            vendor="Managed Agent",
            device_type="Managed Device",
            os_family=reg.get("os"),
            create_if_missing=True,
        )
        conn.commit()
        return {"status": "success", "organization_id": org_id}
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/heartbeat")
async def agent_heartbeat(hb: dict, authorized: bool = Depends(validate_agent_key)):
    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, hb.get("organization_id"))
        cursor.close()
        cursor = None

        agent_service.upsert_agent(
            conn,
            agent_id=hb.get("agent_id", ""),
            organization_id=org_id,
            api_key=settings.AGENT_API_KEY,
            hostname=hb.get("hostname"),
            ip_address=hb.get("device_ip"),
            os_family=hb.get("os"),
            version=hb.get("version"),
            inspection_state=hb.get("web_inspection"),
        )

        managed_device_service.upsert_device(
            conn,
            agent_id=hb.get("agent_id", ""),
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
            agent_id=hb.get("agent_id"),
            hostname=hb.get("hostname"),
            mac=hb.get("device_mac"),
            vendor="Managed Agent",
            device_type="Managed Device",
            os_family=hb.get("os"),
            create_if_missing=True,
        )
        conn.commit()
        return {"status": "success"}
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.get("/web-policy")
async def get_web_policy(
    agent_id: str = Query(...),
    device_ip: str = Query(...),
    organization_id: str | None = Query(default=None),
    authorized: bool = Depends(validate_agent_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, organization_id)
        cursor.close()
        cursor = None
        return web_inspection_service.get_policy(
            conn,
            agent_id=agent_id,
            device_ip=device_ip,
            organization_id=org_id,
        )
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/web-events/batch")
async def receive_web_events(
    events: list = Body(...),
    authorized: bool = Depends(validate_agent_key),
):
    if not events:
        return {"status": "success", "count": 0}

    conn = get_db_connection()
    try:
        count = web_inspection_service.store_events(conn, events)
        return {"status": "success", "count": count}
    except Exception as exc:
        logger.error("Failed to store web inspection events: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to store web events")
    finally:
        conn.close()


@router.post("/devices/batch")
async def receive_devices(devices: list = Body(...), authorized: bool = Depends(validate_agent_key)):
    """Receive ARP-discovered devices from an agent and upsert them into the devices table."""
    if not devices:
        return {"status": "success", "count": 0}

    conn = get_db_connection()
    try:
        count = 0
        for dev in devices:
            logger.debug("Upserting device: %s for org %s", dev.get("ip"), dev.get("organization_id"))
            if device_service.touch_device_seen(
                conn,
                ip=dev.get("ip"),
                organization_id=dev.get("organization_id"),
                seen_at=dev.get("last_seen"),
                agent_id=dev.get("agent_id"),
                hostname=dev.get("hostname"),
                mac=dev.get("mac"),
                vendor=dev.get("vendor"),
                device_type=dev.get("device_type"),
                os_family=dev.get("os_family"),
                create_if_missing=True,
            ):
                count += 1

        conn.commit()
        logger.info("Upserted %s device(s) from agent scan.", count)
        return {"status": "success", "count": count}
    except Exception as e:
        logger.error(f"Failed to upsert devices: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to store devices")
    finally:
        conn.close()
