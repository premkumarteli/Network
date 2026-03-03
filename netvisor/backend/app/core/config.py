import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "NetVisor"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = os.getenv("NETVISOR_SECRET_KEY", "temporary-secret-key-change-it")
    AGENT_API_KEY: str = os.getenv("AGENT_API_KEY", "soc-agent-key-2026")
    
    DB_HOST: str = os.getenv("NETVISOR_DB_HOST", "localhost")
    DB_USER: str = os.getenv("NETVISOR_DB_USER", "root")
    DB_PASSWORD: str = os.getenv("NETVISOR_DB_PASSWORD", "")
    DB_NAME: str = os.getenv("NETVISOR_DB_NAME", "network_security")
    
    BOOTSTRAP_ADMIN_USERNAME: str = os.getenv("NETVISOR_BOOTSTRAP_ADMIN_USERNAME", "admin")
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = os.getenv("NETVISOR_BOOTSTRAP_ADMIN_PASSWORD")

    class Config:
        case_sensitive = True

settings = Settings()
