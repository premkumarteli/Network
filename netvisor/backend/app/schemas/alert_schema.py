from pydantic import BaseModel
from typing import Dict, Any

class AlertBase(BaseModel):
    device_ip: str
    severity: str
    risk_score: float
    breakdown: Dict[str, Any]
    organization_id: str

class Alert(AlertBase):
    id: int
    timestamp: str
    resolved: bool = False
