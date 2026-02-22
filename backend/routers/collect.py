from fastapi import APIRouter, HTTPException, Request, Depends, status
from typing import List
import asyncio
import datetime
import logging
from core.models import PacketLog, AgentRegistration, AgentHeartbeat, GenericResponse
from core.database import packet_queue
from ..config import AGENT_API_KEY
from ..dependencies import rate_limit

logger = logging.getLogger("netvisor.collect")
router = APIRouter(prefix="/api/v1/collect", tags=["Agent Collection"])

async def validate_agent_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != AGENT_API_KEY:
        logger.warning(f"Unauthorized agent access attempt from {request.client.host}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Agent Key")
    return True

@router.post("/packet", response_model=GenericResponse)
async def receive_packet_log(
    log: PacketLog, 
    authorized: bool = Depends(validate_agent_key),
    _: bool = Depends(rate_limit(0.05)) # Max 20 packets/sec per agent IP
):
    try:
        packet_queue.put_nowait(log)
        return {"status": "success", "message": "Log buffered"}
    except asyncio.QueueFull:
        logger.error("Packet queue full - dropping log")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Buffer full - dropping packet")

@router.post("/batch", response_model=GenericResponse)
async def receive_batch_logs(logs: List[PacketLog], authorized: bool = Depends(validate_agent_key)):
    count = 0
    for log in logs:
        try:
            packet_queue.put_nowait(log)
            count += 1
        except asyncio.QueueFull:
            logger.error(f"Packet queue full during batch - buffered {count}/{len(logs)}")
            break
    
    if count == 0 and len(logs) > 0:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Buffer full")
        
    return {"status": "success", "message": f"Buffered {count} logs"}

@router.post("/register")
async def register_agent(reg: AgentRegistration, authorized: bool = Depends(validate_agent_key)):
    from core.database import get_db_connection
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            # Fetch default organization if none provided or if provided doesn't exist
            cursor.execute("SELECT id FROM organizations LIMIT 1")
            org_row = cursor.fetchone()
            org_id = org_row['id'] if org_row else reg.organization_id

            cursor.execute("""
                INSERT INTO agents (id, name, api_key, organization_id, last_seen)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE 
                    last_seen = NOW(),
                    name = VALUES(name),
                    organization_id = VALUES(organization_id)
            """, (reg.agent_id, reg.hostname, AGENT_API_KEY, org_id))
            conn.commit()
            logger.info(f"Agent Registered: {reg.agent_id} | Org: {org_id}")
            return {
                "status": "success", 
                "message": "Connected to Netvisor Professional",
                "organization_id": org_id
            }
        except Exception as e:
            logger.error(f"Registration Error: {e}")
            raise HTTPException(status_code=500, detail="Database registration failed")
        finally:
            conn.close()
    return {"status": "error", "message": "DB connection failed"}

@router.post("/heartbeat", response_model=GenericResponse)
async def agent_heartbeat(hb: AgentHeartbeat, authorized: bool = Depends(validate_agent_key)):
    from core.database import get_db_connection
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE agents SET last_seen = NOW() WHERE id = %s", (hb.agent_id,))
            conn.commit()
            logger.debug(f"Heartbeat from {hb.agent_id}: CPU {hb.cpu_usage}% | RAM {hb.ram_usage}%")
            return {"status": "success", "message": "Heartbeat received"}
        finally:
            conn.close()
    return {"status": "error", "message": "DB connection failed"}
