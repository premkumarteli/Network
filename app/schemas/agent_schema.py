from typing import List, Optional

from pydantic import BaseModel


class AgentSummary(BaseModel):
    agent_id: str
    hostname: str = "Unknown"
    ip_address: str = "-"
    status: str = "Offline"
    last_seen: Optional[str] = None
    heartbeat_age_seconds: Optional[int] = None
    device_count: int = 0
    os_family: Optional[str] = "Unknown"
    version: Optional[str] = "Unknown"
    inspection_enabled: bool = False
    inspection_status: str = "disabled"
    inspection_proxy_running: bool = False
    inspection_ca_installed: bool = False
    inspection_browsers: List[str] = []
    inspection_last_error: Optional[str] = None


class AgentDevice(BaseModel):
    ip: str
    hostname: str = "Unknown"
    mac: Optional[str] = "-"
    vendor: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    os_family: Optional[str] = "Unknown"
    is_online: bool = True
    status: str = "Offline"
    last_seen: Optional[str] = None
    management_mode: str = "observed"


class AgentDetails(AgentSummary):
    online_device_count: int = 0
    devices: List[AgentDevice] = []
