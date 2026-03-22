from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import socketio
import logging
import os

from .core.config import settings
from .api.router import api_router
from .realtime import configure_socket_server
from .db.session import ensure_bootstrap_state, get_db_connection
from .services.application_service import application_service
from .services.system_service import system_service
from .services.web_inspection_service import web_inspection_service

def _resolve_log_level() -> int:
    configured = str(getattr(settings, "LOG_LEVEL", "INFO") or "INFO").upper()
    return getattr(logging, configured, logging.INFO)


# Logging configuration
logging.basicConfig(level=_resolve_log_level())
logging.getLogger("python_multipart").setLevel(logging.WARNING)
logging.getLogger("engineio").setLevel(logging.WARNING)
logging.getLogger("socketio").setLevel(logging.WARNING)
logger = logging.getLogger("netvisor")


def _allowed_origins() -> list[str]:
    raw = getattr(settings, "CORS_ORIGINS_RAW", "")
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["http://127.0.0.1:8000", "http://localhost:8000"]


def _validate_runtime_config() -> None:
    if len(settings.SECRET_KEY or "") < 16:
        raise RuntimeError("NETVISOR_SECRET_KEY must be set to a strong value before startup.")
    if not settings.AGENT_API_KEY:
        raise RuntimeError("AGENT_API_KEY must be set before startup.")
    if not settings.GATEWAY_API_KEY:
        raise RuntimeError("GATEWAY_API_KEY must be set before startup.")

# Socket.IO setup
p_sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins=_allowed_origins())
configure_socket_server(p_sio)

from .services.flow_service import flow_service
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    logger.info("NetVisor Backend Starting Up...")
    _validate_runtime_config()
    ensure_bootstrap_state()
    startup_conn = None
    try:
        startup_conn = get_db_connection()
        application_service.ensure_schema(startup_conn)
        web_inspection_service.ensure_schema(startup_conn)
        if settings.RESET_RUNTIME_ON_STARTUP:
            runtime_result = system_service.prepare_clean_runtime(startup_conn, reason="startup")
            logger.info("Startup runtime reset complete: %s", runtime_result["message"])
    finally:
        if startup_conn:
            startup_conn.close()

    flow_writer_task = asyncio.create_task(flow_service.flow_writer_worker())
    yield
    # Shutdown logic
    logger.info("NetVisor Backend Shutting Down...")
    shutdown_conn = None
    if settings.BACKUP_AND_RESET_ON_SHUTDOWN:
        try:
            shutdown_conn = get_db_connection()
            runtime_result = system_service.backup_and_reset_runtime_data(shutdown_conn, reason="shutdown")
            logger.info("Shutdown runtime backup/reset complete: %s", runtime_result["message"])
        finally:
            if shutdown_conn:
                shutdown_conn.close()

    for task in (flow_writer_task,):
        task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

@app.get("/ping")
async def ping():
    return {"status": "pong"}


@p_sio.event
async def connect(sid, environ):
    logger.info("Socket connected: %s", sid)


@p_sio.event
async def disconnect(sid):
    logger.info("Socket disconnected: %s", sid)

# Static Files
frontend_assets_dir = "frontend/dist/assets"
if os.path.isdir(frontend_assets_dir):
    app.mount("/assets", StaticFiles(directory=frontend_assets_dir), name="assets")
else:
    logger.warning("Frontend assets directory not found: %s", frontend_assets_dir)

# Helper to serve React Index (Catch-All MUST be last, but before SocketIO wrap)
@app.get("/{full_path:path}")
async def serve_react_app(request: Request, full_path: str):
    if full_path.startswith("api") or full_path.startswith("socket.io"):
        return JSONResponse(status_code=404, content={"status": "error", "message": "Not Found"})

    if os.path.exists("frontend/dist/index.html"):
        return FileResponse("frontend/dist/index.html")
    return {"status": "error", "message": "Frontend build not found. Run 'npm run build'."}

# Wrap with Socket.IO
app = socketio.ASGIApp(p_sio, app, socketio_path='socket.io')
