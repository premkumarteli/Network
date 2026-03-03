from pydantic import BaseModel
from typing import Optional

class FlowBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    domain: Optional[str] = None
    packet_count: int
    byte_count: int
    duration: float
    agent_id: str
    organization_id: str

class Flow(FlowBase):
    id: int
    start_time: str
    last_seen: str
