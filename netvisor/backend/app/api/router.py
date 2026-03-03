from fastapi import APIRouter

# Placeholder routers - these will be populated as we migrate modules
from . import health, auth, devices, flows, alerts, agents

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(flows.router, prefix="/flows", tags=["flows"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(agents.router, prefix="/agents", tags=["agents"])
