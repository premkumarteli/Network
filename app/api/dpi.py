from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from ..db.session import get_db_connection
from ..services.web_inspection_service import web_inspection_service
from ..schemas.web_schema import GlobalWebActivityResponse, DeviceWebActivityResponse, WebEventRecord
from ..realtime import emit_event
import logging
import asyncio

router = APIRouter()
logger = logging.getLogger("netvisor.api.dpi")

@router.get("/events", response_model=GlobalWebActivityResponse)
async def get_dpi_events(
    device_id: Optional[str] = Query(None),
    app: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    conn = get_db_connection()
    try:
        # Use web_inspection_service to fetch events, filter in Python for now
        events = web_inspection_service.get_global_activity(conn, organization_id=None, limit=limit)
        if device_id:
            events = [e for e in events if e.get("device_ip") == device_id]
        if app:
            events = [e for e in events if e.get("process_name") == app]
        if domain:
            events = [e for e in events if e.get("base_domain") == domain]
        return {"activity": events}
    finally:
        conn.close()

@router.get("/apps/{app_name}", response_model=GlobalWebActivityResponse)
async def get_dpi_events_by_app(app_name: str, limit: int = Query(100, ge=1, le=500)):
    conn = get_db_connection()
    try:
        events = web_inspection_service.get_global_activity(conn, organization_id=None, limit=limit)
        events = [e for e in events if e.get("process_name") == app_name]
        return {"activity": events}
    finally:
        conn.close()

# WebSocket emission utility (deduplication and async emission)
class DpiEventEmitter:
    def __init__(self):
        self._recent = {}
        self._lock = asyncio.Lock()
        self._dedup_interval = 2  # seconds

    async def emit(self, event: dict):
        key = f"{event.get('device_ip')}|{event.get('process_name')}|{event.get('base_domain')}|{event.get('page_title')}"
        async with self._lock:
            now = asyncio.get_event_loop().time()
            last = self._recent.get(key, 0)
            if now - last < self._dedup_interval:
                return
            self._recent[key] = now
        # YouTube Title Extraction logic
        title = event.get("page_title")
        domain = event.get("base_domain") or ""
        url = event.get("page_url") or ""
        
        if "youtube.com" in domain and (not title or title == "YouTube" or title == "Untitled"):
            from urllib.parse import urlparse, parse_qs
            try:
                parsed = urlparse(url)
                if parsed.path == "/watch":
                    v = parse_qs(parsed.query).get("v")
                    if v:
                        title = f"YouTube Video ({v[0]})"
            except Exception:
                pass

        payload = {
            "timestamp": event.get("last_seen"),
            "app": event.get("process_name"),
            "domain": domain,
            "title": title,
            "search_query": event.get("search_query") or extract_search_query(event),
        }
        await emit_event("dpi_event", payload)

def extract_search_query(event: dict) -> Optional[str]:
    # Google search query extraction
    url = event.get("page_url") or ""
    domain = event.get("base_domain") or ""
    if "google.com" in domain:
        from urllib.parse import urlparse, parse_qs
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query).get("q")
            if q:
                return q[0]
        except Exception:
            pass
    return None

dpi_event_emitter = DpiEventEmitter()

# Example: Call dpi_event_emitter.emit(event) after storing new events in the DB (in web_inspection_service/store_events or API)
