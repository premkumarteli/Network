from fastapi import APIRouter, HTTPException, Request, Depends
from core.models import PacketLog, AgentRegistration, AgentHeartbeat
from core.database import packet_queue
import datetime

router = APIRouter(prefix="/api/v1")

API_KEY = "soc-agent-key-2026"

def verify_api_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return key

@router.post("/collect/packet")
async def collect_packet(log: PacketLog, key: str = Depends(verify_api_key)):
    try:
        await packet_queue.put(log)
        return {"status": "buffered", "queue_size": packet_queue.qsize()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/agent/register")
async def register_agent(reg: AgentRegistration, key: str = Depends(verify_api_key)):
    print(f"[+] Agent Registered: {reg.agent_id} ({reg.hostname})")
    return {"status": "registered", "server_time": datetime.datetime.now().isoformat()}

@router.post("/agent/heartbeat")
async def agent_heartbeat(hb: AgentHeartbeat, key: str = Depends(verify_api_key)):
    # Here you could update an 'agents' table in the DB
    return {"status": "alive", "server_time": datetime.datetime.now().isoformat()}
