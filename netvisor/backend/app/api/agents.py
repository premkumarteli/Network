from fastapi import APIRouter, Depends, HTTPException, Request, status
from ..core.config import settings
from ..db.session import get_db_connection
import logging

logger = logging.getLogger("netvisor.api.agents")
router = APIRouter()

async def validate_agent_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != settings.AGENT_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Agent Key")
    return True

@router.post("/register")
async def register_agent(reg: dict, authorized: bool = Depends(validate_agent_key)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM organizations LIMIT 1")
        org_row = cursor.fetchone()
        org_id = org_row['id'] if org_row else reg.get("organization_id")

        cursor.execute("""
            INSERT INTO agents (id, name, api_key, organization_id, last_seen)
            VALUES (%s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE 
                last_seen = NOW(),
                name = VALUES(name),
                organization_id = VALUES(organization_id)
        """, (reg.get("agent_id"), reg.get("hostname"), settings.AGENT_API_KEY, org_id))
        conn.commit()
        return {"status": "success", "organization_id": org_id}
    finally:
        conn.close()

@router.post("/heartbeat")
async def agent_heartbeat(hb: dict, authorized: bool = Depends(validate_agent_key)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE agents SET last_seen = NOW() WHERE id = %s", (hb.get("agent_id"),))
        conn.commit()
        return {"status": "success"}
    finally:
        conn.close()
