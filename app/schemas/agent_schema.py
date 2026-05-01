from typing import Dict, List, Optional

from pydantic import BaseModel, Field


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
    inspection_ca_status: Optional[str] = None
    inspection_thumbprint_sha256: Optional[str] = None
    inspection_cert_issued_at: Optional[str] = None
    inspection_cert_expires_at: Optional[str] = None
    inspection_rotation_due_at: Optional[str] = None
    inspection_trust_store_match: bool = False
    inspection_trust_scope: Optional[str] = None
    inspection_key_protection: Optional[str] = None
    inspection_proxy_pid: Optional[int] = None
    inspection_proxy_port: Optional[int] = None
    inspection_queue_size: int = 0
    inspection_spooled_event_count: int = 0
    inspection_dropped_event_count: int = 0
    inspection_uploaded_event_count: int = 0
    inspection_upload_failures: int = 0
    inspection_last_event_at: Optional[str] = None
    inspection_last_upload_at: Optional[str] = None
    inspection_drop_reasons: Dict[str, int] = Field(default_factory=dict)


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
