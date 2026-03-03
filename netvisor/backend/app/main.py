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

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netvisor")

# Socket.IO setup
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

from .services.flow_service import flow_service
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    logger.info("NetVisor Backend Starting Up...")
    asyncio.create_task(flow_service.flow_writer_worker())
    yield
    # Shutdown logic
    logger.info("NetVisor Backend Shutting Down...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Adjust in production
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

# Static Files
app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")

# Helper to serve React Index (Catch-All MUST be last, but before SocketIO wrap)
@app.get("/{full_path:path}")
async def serve_react_app(request: Request, full_path: str):
    if full_path.startswith("api") or full_path.startswith("socket.io"):
        return {"status": "error", "message": "Not Found"}

    if os.path.exists("frontend/dist/index.html"):
        return FileResponse("frontend/dist/index.html")
    return {"status": "error", "message": "Frontend build not found. Run 'npm run build'."}

# Wrap with Socket.IO
app = socketio.ASGIApp(sio, app, socketio_path='socket.io')
