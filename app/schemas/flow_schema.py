from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, field_validator

class FlowBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    packet_count: int
    byte_count: int
    duration: float
    agent_id: str
    organization_id: str
    start_time: str
    last_seen: str
    average_packet_size: float
    source_type: Literal["agent", "gateway"] = "agent"
    metadata_only: bool = False

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        return value.upper()

class Flow(FlowBase):
    id: int
    start_time: str
    last_seen: str
