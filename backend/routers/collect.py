from fastapi import APIRouter, HTTPException, Request, Depends
from typing import List
import asyncio
import datetime
from core.models import PacketLog, AgentRegistration, AgentHeartbeat
from core.database import packet_queue
from ..config import AGENT_API_KEY

router = APIRouter(prefix="/api/v1/collect")

def validate_agent_key(request: Request) -> bool:
    key = request.headers.get("X-API-Key")
    if key != AGENT_API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return True

@router.post("/packet")
async def receive_packet_log(log: PacketLog, auth: bool = Depends(validate_agent_key)):
    try:
        packet_queue.put_nowait(log)
        return {"status": "success", "buffered": True}
    except asyncio.QueueFull:
        return {"status": "error", "message": "Buffer full - dropping packet", "error_code": "QUEUE_FULL"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/batch")
async def receive_batch_logs(logs: List[PacketLog], auth: bool = Depends(validate_agent_key)):
    try:
        count = 0
        for log in logs:
            try:
                packet_queue.put_nowait(log)
                count += 1
            except asyncio.QueueFull:
                break
        return {"status": "success", "count": count, "buffered": True}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/register")
async def register_agent(reg: AgentRegistration, auth: bool = Depends(validate_agent_key)):
    print(f"[+] Agent Registered: {reg.agent_id} ({reg.hostname})")
    return {"status": "registered", "server_time": datetime.datetime.now().isoformat()}

@router.post("/heartbeat")
async def agent_heartbeat(hb: AgentHeartbeat, auth: bool = Depends(validate_agent_key)):
    return {"status": "alive", "server_time": datetime.datetime.now().isoformat()}
