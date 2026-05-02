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
    AGENT_MASTER_KEY: str = Field(default="", validation_alias="NETVISOR_AGENT_MASTER_KEY")
    GATEWAY_MASTER_KEY: str = Field(default="", validation_alias="NETVISOR_GATEWAY_MASTER_KEY")
    AGENT_NONCE_TTL_SECONDS: int = Field(default=300, validation_alias="NETVISOR_AGENT_NONCE_TTL_SECONDS")
    AGENT_MAX_CLOCK_SKEW_SECONDS: int = Field(default=60, validation_alias="NETVISOR_AGENT_MAX_CLOCK_SKEW_SECONDS")
    ACCESS_TOKEN_MINUTES: int = Field(default=30, validation_alias="NETVISOR_ACCESS_TOKEN_MINUTES")
    AUTH_COOKIE_NAME: str = Field(default="netvisor_session", validation_alias="NETVISOR_AUTH_COOKIE_NAME")
    AUTH_COOKIE_SAMESITE: str = Field(default="lax", validation_alias="NETVISOR_AUTH_COOKIE_SAMESITE")
    AUTH_COOKIE_SECURE: bool = Field(default=False, validation_alias="NETVISOR_AUTH_COOKIE_SECURE")
    AUTH_COOKIE_DOMAIN: Optional[str] = Field(default=None, validation_alias="NETVISOR_AUTH_COOKIE_DOMAIN")
    AUTH_COOKIE_PATH: str = Field(default="/", validation_alias="NETVISOR_AUTH_COOKIE_PATH")
    CSRF_COOKIE_NAME: str = Field(default="XSRF-TOKEN", validation_alias="NETVISOR_CSRF_COOKIE_NAME")
    CSRF_HEADER_NAME: str = Field(default="X-XSRF-TOKEN", validation_alias="NETVISOR_CSRF_HEADER_NAME")
    RELEASE_VERSION: str = Field(default="", validation_alias="NETVISOR_RELEASE_VERSION")
    RELEASE_CHANNEL: str = Field(default="dev", validation_alias="NETVISOR_RELEASE_CHANNEL")
    GIT_COMMIT: str = Field(default="", validation_alias="NETVISOR_GIT_COMMIT")
    BUILD_TIMESTAMP: str = Field(default="", validation_alias="NETVISOR_BUILD_TIMESTAMP")
    LOGIN_LOCKOUT_THRESHOLD: int = Field(default=5, validation_alias="NETVISOR_LOGIN_LOCKOUT_THRESHOLD")
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, validation_alias="NETVISOR_LOGIN_LOCKOUT_MINUTES")
    BACKEND_TLS_PINS_JSON: str = Field(default="[]", validation_alias="NETVISOR_BACKEND_TLS_PINS_JSON")
    AUTH_LOGIN_RATE_LIMIT_PER_MINUTE: int = Field(default=20, validation_alias="NETVISOR_AUTH_LOGIN_RATE_LIMIT_PER_MINUTE")
    AUTH_REGISTER_RATE_LIMIT_PER_MINUTE: int = Field(default=5, validation_alias="NETVISOR_AUTH_REGISTER_RATE_LIMIT_PER_MINUTE")
    AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE: int = Field(default=30, validation_alias="NETVISOR_AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE")
    AGENT_CONTROL_RATE_LIMIT_PER_MINUTE: int = Field(default=240, validation_alias="NETVISOR_AGENT_CONTROL_RATE_LIMIT_PER_MINUTE")
    AGENT_FLOW_RATE_LIMIT_PER_MINUTE: int = Field(default=1200, validation_alias="NETVISOR_AGENT_FLOW_RATE_LIMIT_PER_MINUTE")
    AGENT_ENROLLMENT_PENDING_TTL_SECONDS: int = Field(
        default=86400,
        validation_alias="NETVISOR_AGENT_ENROLLMENT_PENDING_TTL_SECONDS",
    )
    AGENT_ENROLLMENT_RETRY_SECONDS: int = Field(
        default=15,
        validation_alias="NETVISOR_AGENT_ENROLLMENT_RETRY_SECONDS",
    )
    ADMIN_MUTATION_RATE_LIMIT_PER_MINUTE: int = Field(default=30, validation_alias="NETVISOR_ADMIN_MUTATION_RATE_LIMIT_PER_MINUTE")
    FLOW_WORKER_MODE: str = Field(default="embedded", validation_alias="NETVISOR_FLOW_WORKER_MODE")
    FLOW_WORKER_POLL_SECONDS: float = Field(default=1.0, validation_alias="NETVISOR_FLOW_WORKER_POLL_SECONDS")
    FLOW_WORKER_CLAIM_LIMIT: int = Field(default=10, validation_alias="NETVISOR_FLOW_WORKER_CLAIM_LIMIT")
    FLOW_WORKER_HEARTBEAT_SECONDS: float = Field(default=5.0, validation_alias="NETVISOR_FLOW_WORKER_HEARTBEAT_SECONDS")
    FLOW_WORKER_ALIVE_SECONDS: int = Field(default=15, validation_alias="NETVISOR_FLOW_WORKER_ALIVE_SECONDS")
    FLOW_QUEUE_STATUS_CACHE_SECONDS: float = Field(default=1.0, validation_alias="NETVISOR_FLOW_QUEUE_STATUS_CACHE_SECONDS")
    FLOW_INGEST_MAX_ATTEMPTS: int = Field(default=5, validation_alias="NETVISOR_FLOW_INGEST_MAX_ATTEMPTS")
    FLOW_INGEST_RETRY_SECONDS: int = Field(default=5, validation_alias="NETVISOR_FLOW_INGEST_RETRY_SECONDS")
    FLOW_INGEST_CLAIM_TTL_SECONDS: int = Field(default=120, validation_alias="NETVISOR_FLOW_INGEST_CLAIM_TTL_SECONDS")
    FLOW_INGEST_MAX_PENDING_FLOWS: int = Field(default=50000, validation_alias="NETVISOR_FLOW_INGEST_MAX_PENDING_FLOWS")
    FLOW_INGEST_MAX_LAG_SECONDS: int = Field(default=30, validation_alias="NETVISOR_FLOW_INGEST_MAX_LAG_SECONDS")
    FLOW_ALERT_DEDUPE_WINDOW_SECONDS: int = Field(
        default=300,
        validation_alias="NETVISOR_FLOW_ALERT_DEDUPE_WINDOW_SECONDS",
    )

    DB_HOST: str = Field(default="localhost", validation_alias="NETVISOR_DB_HOST")
    DB_USER: str = Field(default="root", validation_alias="NETVISOR_DB_USER")
    DB_PASSWORD: str = Field(default="", validation_alias="NETVISOR_DB_PASSWORD")
    DB_NAME: str = Field(default="network_security", validation_alias="NETVISOR_DB_NAME")
    SINGLE_ORG_MODE: bool = Field(default=True, validation_alias="NETVISOR_SINGLE_ORG_MODE")
    DEFAULT_ORGANIZATION_ID: Optional[str] = Field(default=None, validation_alias="NETVISOR_DEFAULT_ORGANIZATION_ID")

    BOOTSTRAP_ADMIN_USERNAME: str = Field(default="admin", validation_alias="NETVISOR_BOOTSTRAP_ADMIN_USERNAME")
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = Field(default=None, validation_alias="NETVISOR_BOOTSTRAP_ADMIN_PASSWORD")
    ALLOW_SELF_REGISTER: bool = Field(default=False, validation_alias="NETVISOR_ALLOW_SELF_REGISTER")
    ALLOW_LAN_HTTP: bool = Field(default=False, validation_alias="NETVISOR_ALLOW_LAN_HTTP")
    RESET_RUNTIME_ON_STARTUP: bool = Field(default=False, validation_alias="NETVISOR_RESET_RUNTIME_ON_STARTUP")
    BACKUP_AND_RESET_ON_SHUTDOWN: bool = Field(default=False, validation_alias="NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN")
    CORS_ORIGINS_RAW: str = Field(
        default="http://127.0.0.1:8000,http://localhost:8000",
        validation_alias="NETVISOR_CORS_ORIGINS",
    )
    LOG_LEVEL: str = Field(default="INFO", validation_alias="NETVISOR_LOG_LEVEL")
    DEBUG: bool = Field(default=False, validation_alias="NETVISOR_DEBUG")
    GEOIP_ASN_DB_PATH: str = Field(
        default=str(PROJECT_ROOT / "database" / "GeoLite2-ASN.mmdb"),
        validation_alias="NETVISOR_GEOIP_ASN_DB_PATH",
    )
    BACKUP_DIR: str = Field(
        default=str(PROJECT_ROOT / "runtime" / "backups" / "server"),
        validation_alias="NETVISOR_BACKUP_DIR",
    )
    BACKUP_RETENTION_DAYS: int = Field(default=30, validation_alias="NETVISOR_BACKUP_RETENTION_DAYS")

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()
