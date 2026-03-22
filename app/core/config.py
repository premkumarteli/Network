from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    PROJECT_NAME: str = "NetVisor"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"

    SECRET_KEY: str = Field(default="", validation_alias="NETVISOR_SECRET_KEY")
    AGENT_API_KEY: str = Field(default="", validation_alias="AGENT_API_KEY")
    GATEWAY_API_KEY: str = Field(default="", validation_alias="GATEWAY_API_KEY")

    DB_HOST: str = Field(default="localhost", validation_alias="NETVISOR_DB_HOST")
    DB_USER: str = Field(default="root", validation_alias="NETVISOR_DB_USER")
    DB_PASSWORD: str = Field(default="", validation_alias="NETVISOR_DB_PASSWORD")
    DB_NAME: str = Field(default="network_security", validation_alias="NETVISOR_DB_NAME")
    SINGLE_ORG_MODE: bool = Field(default=True, validation_alias="NETVISOR_SINGLE_ORG_MODE")
    DEFAULT_ORGANIZATION_ID: Optional[str] = Field(default=None, validation_alias="NETVISOR_DEFAULT_ORGANIZATION_ID")

    BOOTSTRAP_ADMIN_USERNAME: str = Field(default="admin", validation_alias="NETVISOR_BOOTSTRAP_ADMIN_USERNAME")
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = Field(default=None, validation_alias="NETVISOR_BOOTSTRAP_ADMIN_PASSWORD")
    RESET_RUNTIME_ON_STARTUP: bool = Field(default=True, validation_alias="NETVISOR_RESET_RUNTIME_ON_STARTUP")
    BACKUP_AND_RESET_ON_SHUTDOWN: bool = Field(default=True, validation_alias="NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN")
    CORS_ORIGINS_RAW: str = Field(
        default="http://127.0.0.1:8000,http://localhost:8000",
        validation_alias="NETVISOR_CORS_ORIGINS",
    )
    LOG_LEVEL: str = Field(default="INFO", validation_alias="NETVISOR_LOG_LEVEL")
    GEOIP_ASN_DB_PATH: str = Field(
        default=str(PROJECT_ROOT / "database" / "GeoLite2-ASN.mmdb"),
        validation_alias="NETVISOR_GEOIP_ASN_DB_PATH",
    )
    BACKUP_DIR: str = Field(
        default=str(PROJECT_ROOT / "runtime" / "backups" / "server"),
        validation_alias="NETVISOR_BACKUP_DIR",
    )

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()
if not settings.GATEWAY_API_KEY:
    settings.GATEWAY_API_KEY = settings.AGENT_API_KEY
