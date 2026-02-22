from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse, JSONResponse
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware
from colorama import Fore
import asyncio
import os
import socketio
import logging
import time
from dotenv import load_dotenv

load_dotenv()

# --- Centralized Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netvisor")

# --- Socket.IO Server ---
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

from core.database import init_db, db_writer_worker
from .config import SECRET_KEY
from .routers import auth, collect, api, policy
from core.state import state

# --- Global Exception Handler ---
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "An internal server error occurred.", "details": str(exc)}
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    state.start_time = time.time()
    init_db()
    asyncio.create_task(db_writer_worker())
    
    # Start periodic baseline computation (every 1 hour)
    async def baseline_timer():
        from services.baseline_service import baseline_service
        while True:
            baseline_service.compute_all_baselines()
            await asyncio.sleep(3600)
            
    asyncio.create_task(baseline_timer())
    
    if not os.path.exists("data/backups"):
        os.makedirs("data/backups")
        
    print(f"{Fore.GREEN}[+] Netvisor Server Industrial Layer is online.")
    yield
    # SHUTDOWN
    print(f"\n{Fore.YELLOW}[!] Server stopping...")
    from core.database import drain_packet_queue
    from .services.data_service import export_to_csv_task, truncate_data
    
    await drain_packet_queue()
    
    print(f"{Fore.CYAN}[*] Archiving session data...")
    csv_file = export_to_csv_task()
    if csv_file and csv_file != "empty":
        print(f"{Fore.GREEN}[+] Data backed up: {csv_file}")
        if truncate_data():
            print(f"{Fore.GREEN}[+] Database truncated for next run.")
        else:
            print(f"{Fore.RED}[X] Failed to truncate database.")
    else:
        print(f"{Fore.YELLOW}[!] No data to archive or export failed.")

app = FastAPI(
    title="Netvisor | Industrial SOC", 
    lifespan=lifespan,
    exception_handlers={Exception: global_exception_handler}
)

# --- CORS Hardening ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/ping")
async def ping():
    return {"status": "pong"}

# Middleware
@app.middleware("http")
async def maintenance_middleware(request: Request, call_next):
    exempt_paths = ["/maintenance", "/login", "/register", "/assets", "/api/v1/collect"]
    if state.maintenance_mode and not any(request.url.path.startswith(p) for p in exempt_paths):
        if "user_id" not in request.session:
            return RedirectResponse(url="/maintenance")
    return await call_next(request)

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY,
    https_only=os.getenv("SECURE_COOKIES", "False").lower() == "true",
    same_site="lax",
    max_age=3600 # 1 hour session expiration for enhanced security
)

# Static Files
app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")


# Routers
# NOTE: API routers must be included BEFORE the catch-all frontend route
app.include_router(auth.router)
app.include_router(collect.router)
app.include_router(policy.router)
app.include_router(api.router, prefix="/api")


# Socket.IO Events
@sio.event
async def connect(sid, environ):
    logger.info(f"Socket connected: {sid}")

@sio.event
async def disconnect(sid):
    logger.info(f"Socket disconnected: {sid}")

# Wrap with Socket.IO
# Restrict CORS to specific origins in production
cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
if len(cors_origins) == 1 and cors_origins[0] == "*":
    cors_origins = "*"

# Helper to serve React Index (Catch-All MUST be last, but before SocketIO wrap)
@app.get("/{full_path:path}")
async def serve_react_app(request: Request, full_path: str):
    if full_path.startswith("api") or full_path.startswith("socket.io"):
        return {"status": "error", "message": "Not Found"}

    if os.path.exists("frontend/dist/index.html"):
        return FileResponse("frontend/dist/index.html")
    return {"status": "error", "message": "Frontend build not found. Run 'npm run build'."}

app = socketio.ASGIApp(sio, app, socketio_path='socket.io')
