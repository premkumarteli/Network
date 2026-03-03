from pydantic import BaseModel
from typing import Optional, List

class DeviceBase(BaseModel):
    ip: str
    mac: Optional[str] = "-"
    hostname: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    os_family: Optional[str] = "Unknown"
    brand: Optional[str] = "Unknown"
    organization_id: str

class Device(DeviceBase):
    id: str
    is_online: bool = True
    last_seen: str
    risk_score: int = 0
    risk_level: str = "LOW"
    confidence: str = "low"

class DeviceRisk(BaseModel):
    device_id: str
    current_score: float
    risk_level: str
    reasons: List[str]
    last_updated: str
