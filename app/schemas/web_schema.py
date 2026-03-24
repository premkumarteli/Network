from __future__ import annotations

from typing import List, Optional

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
    search_query: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class DeviceWebActivityResponse(BaseModel):
    device_ip: str
    activity: List[WebEventRecord] = []


class GlobalWebEventRecord(WebEventRecord):
    device_ip: str
    agent_id: str


class GlobalWebActivityResponse(BaseModel):
    activity: List[GlobalWebEventRecord] = []



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
    updated_at: Optional[str] = None


class DeviceInspectionStatus(InspectionPolicyResponse):
    browser_support: List[str] = []
    proxy_running: bool = False
    ca_installed: bool = False
    status: str = "disabled"
    last_error: Optional[str] = None
    last_event_at: Optional[str] = None
    recent_event_count: int = 0
