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
    organization_id: str
    device_name: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    os_family: Optional[str] = "Unknown"
    brand: Optional[str] = "Unknown"
    mac_address: Optional[str] = "-"
    identity_confidence: Optional[str] = "low"


class FlowLog(BaseModel):
    """
    Flow-level summary object produced by agents.
    No risk or detection fields here; purely features.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    last_seen: str
    packet_count: int
    byte_count: int
    duration: float
    average_packet_size: float
    agent_id: str
    organization_id: str

class DeviceRisk(BaseModel):
    device_id: str
    ip_address: str
    current_score: float
    risk_level: str # LOW, MEDIUM, HIGH, CRITICAL
    reasons: List[str]
    last_updated: str
    organization_id: str

class RiskHistory(BaseModel):
    device_ip: str
    risk_score: float
    severity: str
    timestamp: str
    organization_id: str

class DeviceBaseline(BaseModel):
    device_id: str
    ip_address: str
    avg_connections_per_min: float
    avg_unique_destinations: float
    avg_flow_duration: float
    std_dev_connections: float
    last_computed: str
    organization_id: str

class Alert(BaseModel):
    device_ip: str
    severity: str
    risk_score: float
    breakdown_json: str # Store as JSON string for flexibility
    timestamp: str
    resolved: bool = False
    organization_id: str

# --- API REQUEST SCHEMAS ---

class UserLogin(BaseModel) :
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str
    role: Optional[str] = "viewer"

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
    organization_id: str

class AgentHeartbeat(BaseModel):
    agent_id: str
    status: str
    dropped_packets: int
    time: str
    organization_id: str
    cpu_usage: Optional[float] = 0.0
    ram_usage: Optional[float] = 0.0
    inventory_size: Optional[int] = 0

# --- API RESPONSE SCHEMAS ---

class GenericResponse(BaseModel):
    status: str
    message: Optional[str] = None

class DeviceResponse(BaseModel):
    ip: str
    mac: str
    hostname: str
    traffic: float
    is_online: bool
    last_seen: str
    type: str
    os: str
    brand: str
    confidence: str
    risk_score: Optional[int] = 0
    risk_level: Optional[str] = "LOW"

class SystemHealthResponse(BaseModel):
    status: str
    cpu_usage: float
    ram_usage: float
    uptime_hours: float

class AdminStatsResponse(BaseModel):
    hostname: str
    local_ip: str
    cpu_percent: float
    mem_used_mb: float
    mem_total_mb: float
    maintenance_mode: bool

class ActivityEntry(BaseModel):
    time: str
    src_ip: str
    dst_ip: str
    domain: str
    protocol: str
    size: int
    device: str
    os: str
    brand: str
    mac: str
    confidence: str
    severity: str

class AdminLogEntry(BaseModel):
    time: str
    action: str
    details: str

class VPNLogEntry(BaseModel):
    time: str
    src_ip: str
    score: float
    reason: str

class PolicyUpdate(BaseModel):
    blocked_domains: List[str]
    vpn_restriction: bool
    alert_threshold: int
    organization_id: str

class LogsResponse(BaseModel):
    admin: List[AdminLogEntry]
    vpn: List[VPNLogEntry]
