from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from ..db.session import get_db_connection
from ..services.application_service import application_service
from ..services.web_inspection_service import web_inspection_service
from ..utils.domain_intelligence import get_service_info
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
        normalized = app_name.strip().lower()
        filtered = []
        for event in events:
            base_domain = event.get("base_domain") or ""
            service_name, _ = get_service_info(base_domain)
            classified_name = application_service.classify_by_domain(base_domain) or ""
            if service_name.strip().lower() == normalized or classified_name.strip().lower() == normalized:
                filtered.append(event)
        events = filtered
        return {"activity": events}
    finally:
        conn.close()


@router.get("/status")
async def get_dpi_status():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_agents,
                SUM(CASE WHEN inspection_enabled = 1 THEN 1 ELSE 0 END) AS enabled_agents,
                SUM(CASE WHEN inspection_proxy_running = 1 THEN 1 ELSE 0 END) AS running_agents,
                SUM(CASE WHEN inspection_ca_installed = 1 THEN 1 ELSE 0 END) AS cert_agents
            FROM agents
            """
        )
        agent_row = cursor.fetchone() or {}
        cursor.execute(
            """
            SELECT
                MAX(last_seen) AS last_activity,
                COUNT(*) AS recent_events
            FROM web_events
            WHERE COALESCE(last_seen, created_at) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE)
            """
        )
        event_row = cursor.fetchone() or {}
    finally:
        cursor.close()
        conn.close()

    enabled_agents = int(agent_row.get("enabled_agents") or 0)
    running_agents = int(agent_row.get("running_agents") or 0)
    cert_agents = int(agent_row.get("cert_agents") or 0)
    recent_events = int(event_row.get("recent_events") or 0)

    state = "disabled"
    if enabled_agents > 0:
        state = "enabled" if running_agents == enabled_agents and cert_agents == enabled_agents else "degraded"

    return {
        "state": state,
        "proxy": "running" if running_agents > 0 else "stopped",
        "certificate": "installed" if cert_agents > 0 else "not_installed",
        "lastActivity": event_row.get("last_activity"),
        "eps": recent_events / 60 if recent_events else 0,
    }

# WebSocket emission utility (deduplication and async emission)
class DpiEventEmitter:
    def __init__(self):
        self._recent = {}
        self._lock = asyncio.Lock()
        self._dedup_interval = 2  # seconds

    async def emit(self, event: dict):
        device_ip = event.get("device_ip")
        content_id = str(event.get("content_id") or "").strip()
        page_url = str(event.get("page_url") or "").strip()
        page_title = str(event.get("page_title") or "").strip()
        tab_key = content_id or page_url or page_title
        key = f"{device_ip}|{event.get('process_name')}|{event.get('base_domain')}|{tab_key}"
        async with self._lock:
            now = asyncio.get_event_loop().time()
            last = self._recent.get(key, 0)
            if now - last < self._dedup_interval:
                return
            self._recent[key] = now
        # YouTube Title Extraction logic
        title = event.get("page_title")
        domain = event.get("base_domain") or ""
        url = page_url
        
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
            "organization_id": event.get("organization_id"),
            "timestamp": event.get("last_seen"),
            "device_ip": device_ip,
            "process_name": event.get("process_name"),
            "browser_name": event.get("browser_name") or "Unknown",
            "domain": domain,
            "page_url": url,
            "page_title": title or "Untitled Page",
            "content_category": event.get("content_category") or "web",
            "content_id": content_id or event.get("content_id"),
            "search_query": event.get("search_query") or extract_search_query(event),
            "source_type": event.get("source_type") or "agent",
            "metadata_only": bool(event.get("metadata_only")),
        }
        await emit_event("dpi_event", payload)

def extract_search_query(event: dict) -> Optional[str]:
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
    if "bing.com" in domain:
        from urllib.parse import urlparse, parse_qs
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query).get("q")
            if q:
                return q[0]
        except Exception:
            pass
        return None
    if "duckduckgo.com" in domain or "search.brave.com" in domain:
        from urllib.parse import urlparse, parse_qs
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query).get("q") or parse_qs(parsed.query).get("query") or parse_qs(parsed.query).get("p")
            if q:
                return q[0]
        except Exception:
            pass
    return None

dpi_event_emitter = DpiEventEmitter()

# Example: Call dpi_event_emitter.emit(event) after storing new events in the DB (in web_inspection_service/store_events or API)
