from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class WebEventRecord(BaseModel):
    page_url: str
    base_domain: str
    page_title: str = "Untitled"
    browser_name: str = "Unknown"
    process_name: str = "unknown"
    content_category: str = "web"
    content_id: Optional[str] = None
    http_method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    request_bytes: int = 0
    response_bytes: int = 0
    snippet_redacted: Optional[str] = None
    snippet_hash: Optional[str] = None
    search_query: Optional[str] = None
    event_count: int = 1
    risk_level: str = "safe"
    threat_msg: Optional[str] = None
    confidence_score: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class WebEvidenceGroupRecord(WebEventRecord):
    group_key: str
    group_label: str
    device_ip: str
    agent_id: Optional[str] = None
    page_urls: List[str] = Field(default_factory=list)
    page_titles: List[str] = Field(default_factory=list)
    content_ids: List[str] = Field(default_factory=list)
    search_queries: List[str] = Field(default_factory=list)


class DeviceWebActivityResponse(BaseModel):
    device_ip: str
    activity: List[WebEventRecord] = []


class GlobalWebEventRecord(WebEventRecord):
    device_ip: str
    agent_id: str


class GlobalWebActivityResponse(BaseModel):
    activity: List[GlobalWebEventRecord] = []


class DeviceWebEvidenceGroupResponse(BaseModel):
    device_ip: str
    activity: List[WebEvidenceGroupRecord] = []


class GlobalWebEvidenceGroupResponse(BaseModel):
    activity: List[WebEvidenceGroupRecord] = []



class InspectionPolicyUpdate(BaseModel):
    device_ip: str
    inspection_enabled: Optional[bool] = None
    allowed_processes: Optional[List[str]] = None
    allowed_domains: Optional[List[str]] = None
    snippet_max_bytes: Optional[int] = Field(default=None, ge=0, le=256)


class InspectionPolicyResponse(BaseModel):
    agent_id: Optional[str] = None
    device_ip: str
    inspection_enabled: bool = False
    allowed_processes: List[str] = []
    allowed_domains: List[str] = []
    snippet_max_bytes: int = 256
    privacy_guard_enabled: bool = True
    sensitive_destination_bypass_enabled: bool = True
    updated_at: Optional[str] = None


class DeviceInspectionStatus(InspectionPolicyResponse):
    browser_support: List[str] = []
    proxy_running: bool = False
    ca_installed: bool = False
    ca_status: str = "missing"
    days_until_expiry: Optional[int] = None
    days_until_rotation_due: Optional[int] = None
    expires_soon: Optional[bool] = None
    rotation_due_soon: Optional[bool] = None
    status: str = "disabled"
    last_error: Optional[str] = None
    last_event_at: Optional[str] = None
    recent_event_count: int = 0
    last_upload_at: Optional[str] = None
    proxy_port: Optional[int] = None
    proxy_pid: Optional[int] = None
    queue_size: int = 0
    spooled_event_count: int = 0
    dropped_event_count: int = 0
    uploaded_event_count: int = 0
    upload_failures: int = 0
    last_drop_reason: Optional[str] = None
    drop_reasons: Dict[str, int] = Field(default_factory=dict)
