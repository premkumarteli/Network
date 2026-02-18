from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware
from colorama import Fore
import asyncio
import os
import logging

# Initialize logging for production-grade traceability
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netvisor")

from core.database import init_db, db_writer_worker
from .config import SECRET_KEY
from .routers import auth, collect, api, dashboard
from .config import MAINTENANCE_MODE

@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    init_db()
    asyncio.create_task(db_writer_worker())
    
    if not os.path.exists("data/backups"):
        os.makedirs("data/backups")
        
    print(f"{Fore.GREEN}[+] Netvisor Server Industrial Layer is online.")
    yield
    # SHUTDOWN
    print(f"\n{Fore.YELLOW}[!] Server stopping...")

app = FastAPI(title="Netvisor | Industrial SOC", lifespan=lifespan)

# Middleware
@app.middleware("http")
async def maintenance_middleware(request: Request, call_next):
    exempt_paths = ["/maintenance", "/login", "/register", "/static", "/api/v1/collect"]
    if MAINTENANCE_MODE and not any(request.url.path.startswith(p) for p in exempt_paths):
        if "user_id" not in request.session:
            return RedirectResponse(url="/maintenance")
    return await call_next(request)

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY,
    https_only=True,   # Enhanced security: ensures session cookie is only sent over HTTPS
    same_site="lax"    # Protects against CSRF while maintaining user experience
)

# Static Files
# Assuming running from root, static is in root/static
app.mount("/static", StaticFiles(directory="static"), name="static")

# Routers
app.include_router(dashboard.router)
app.include_router(auth.router)
app.include_router(collect.router)
app.include_router(api.router)
