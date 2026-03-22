from pydantic import BaseModel
from typing import Optional, List


class DeviceBase(BaseModel):
    ip: str
    mac: Optional[str] = "-"
    hostname: Optional[str] = "Unknown"
    vendor: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    os_family: Optional[str] = "Unknown"
    brand: Optional[str] = "Unknown"
    organization_id: Optional[str] = None


class Device(DeviceBase):
    id: int | str
    agent_id: Optional[str] = None
    is_online: bool = True
    status: str = "Offline"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    risk_score: float = 0
    risk_level: str = "LOW"
    confidence: str = "low"
    management_mode: str = "byod"


class DeviceRisk(BaseModel):
    device_id: str
    current_score: float
    risk_level: str
    reasons: List[str]
    last_updated: str
