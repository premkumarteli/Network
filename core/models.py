from pydantic import BaseModel
from typing import Optional, List

class PacketLog(BaseModel):
    time: str
    src_ip: str
    dst_ip: Optional[str] = "-"
    domain: str
    protocol: Optional[str] = "DNS"
    port: Optional[str] = "53"
    risk_score: Optional[int] = 0
    entropy: Optional[float] = 0.0
    severity: Optional[str] = "LOW"
    size: Optional[int] = 0
    agent_id: Optional[str] = "GATEWAY_SENSE_01"
    device_name: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    os_family: Optional[str] = "Unknown"
    brand: Optional[str] = "Unknown"
    mac_address: Optional[str] = "-"
    identity_confidence: Optional[str] = "low"

class HotspotRequest(BaseModel):
    action: str

class SystemConfigRequest(BaseModel):
    active: bool

class AgentRegistration(BaseModel):
    agent_id: str
    os: str
    hostname: str
    version: str
    time: str

class AgentHeartbeat(BaseModel):
    agent_id: str
    status: str
    dropped_packets: int
    time: str
    cpu_usage: Optional[float] = 0.0
    ram_usage: Optional[float] = 0.0
    inventory_size: Optional[int] = 0
