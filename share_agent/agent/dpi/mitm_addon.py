import sys
from pathlib import Path
import json
import os
import re
from html import unescape
from urllib.parse import parse_qs, urlsplit
from datetime import datetime, timezone

# Add project root to sys.path to allow importing from 'app'
root = Path(__file__).resolve().parent.parent.parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from shared.collector import DpiObservation
from shared.intel import get_base_domain, get_service_info, is_sensitive_destination, normalize_host

EVENT_PREFIX = "__NETVISOR_WEB_EVENT__"
ALLOWED_DOMAINS = {
    item
    for item in json.loads(os.getenv("NETVISOR_ALLOWED_DOMAINS_JSON", "[]") or "[]")
    if str(item).strip()
}
SNIPPET_MAX_BYTES = min(max(int(os.getenv("NETVISOR_SNIPPET_MAX_BYTES", "256")), 0), 256)


def _find_header(headers, name: str) -> str:
    target = str(name or "").lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _browser_from_name(name: str) -> tuple[str, str]:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return "Unknown", "unknown"
    if "edge" in lowered or "edg" in lowered:
        return "Edge", "msedge.exe"
    if "chrome" in lowered or "chromium" in lowered:
        return "Chrome", "chrome.exe"
    if "firefox" in lowered:
        return "Firefox", "firefox.exe"
    if "safari" in lowered and "chrome" not in lowered:
        return "Safari", "safari.exe"
    if "python" in lowered:
        return "Python", "python.exe"
    return "Unknown", "unknown"


def infer_browser_identity(headers) -> tuple[str, str]:
    sec_ch_ua = _find_header(headers, "sec-ch-ua")
    for marker in ("Microsoft Edge", "Google Chrome", "Chromium", "Firefox", "Safari"):
        if marker.lower() in sec_ch_ua.lower():
            return _browser_from_name(marker)

    user_agent = _find_header(headers, "user-agent")
    lowered_user_agent = user_agent.lower()
    if "edg/" in lowered_user_agent:
        return "Edge", "msedge.exe"
    if "chrome/" in lowered_user_agent or "chromium/" in lowered_user_agent:
        return "Chrome", "chrome.exe"
    if "firefox/" in lowered_user_agent:
        return "Firefox", "firefox.exe"
    if "safari/" in lowered_user_agent and "chrome/" not in lowered_user_agent:
        return "Safari", "safari.exe"
    if "python" in lowered_user_agent:
        return "Python", "python.exe"
    return "Unknown", "unknown"


def _preferred_domain_label(host: str | None) -> str | None:
    normalized_host = normalize_host(host)
    if not normalized_host:
        return None

    base_domain = get_base_domain(normalized_host) or normalized_host
    exact_name, exact_category = get_service_info(normalized_host)
    base_name, base_category = get_service_info(base_domain)
    if normalized_host != base_domain and (exact_name != base_name or exact_category != base_category):
        return normalized_host
    return base_domain


def extract_page_title(body: str | bytes | None) -> str | None:
    if body in (None, "", b""):
        return None
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = body

    patterns = (
        r"<title[^>]*>(.*?)</title>",
        r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']',
        r'<meta[^>]+name=["\']title["\'][^>]+content=["\'](.*?)["\']',
        r'"title"\s*:\s*"([^"]+)"',
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            title = unescape(match.group(1)).strip()
            if title:
                return re.sub(r"\s+", " ", title)[:255]
    return None


def extract_site_details(url: str, page_title: str | None) -> tuple[str, str | None, str | None, str]:
    """Returns (category, content_id, search_query, service_name)."""
    split = urlsplit(url or "")
    host = normalize_host(split.netloc)
    base_domain = get_base_domain(host) or host
    query = parse_qs(split.query)

    service_name, category = get_service_info(host or base_domain)

    if category == "search":
        q = (
            query.get("q")
            or query.get("p")
            or query.get("query")
            or query.get("text")
            or [None]
        )[0]
        return category, None, q, service_name

    if service_name == "YouTube":
        v_id = (query.get("v") or [None])[0]
        playlist_id = (query.get("list") or [None])[0]
        return "video", v_id or playlist_id, None, service_name

    if service_name == "YouTube Video":
        # Video stream chunks
        v_id = (query.get("id") or [None])[0]
        return category, v_id, None, service_name

    if category == "dev" and base_domain == "github.com":
        path = split.path.strip("/").split("/")
        if len(path) >= 2:
            repo = "/".join(path[:2])
            if len(path) >= 4 and path[2] in {"issues", "pull"}:
                return category, f"{repo}#{path[3]}", None, service_name
            return category, repo, None, service_name

    if category == "ai":
        segments = [segment for segment in split.path.strip("/").split("/") if segment]
        if segments:
            return category, "/".join(segments[:3]), None, service_name
        prompt_hint = (
            query.get("q")
            or query.get("prompt")
            or query.get("query")
            or [None]
        )[0]
        if prompt_hint:
            return category, None, prompt_hint, service_name

    return category, None, None, service_name


def extract_site_metadata(url: str, page_title: str | None) -> tuple[str, str | None]:
    category, content_id, _, _ = extract_site_details(url, page_title)
    return category, content_id


def build_event(flow) -> dict | None:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    if not request or not response:
        return None

    host = normalize_host(getattr(request, "pretty_host", None) or getattr(request, "host", None))
    base_domain = _preferred_domain_label(host)
    if not base_domain:
        return None
    if is_sensitive_destination(base_domain):
        return None
    if ALLOWED_DOMAINS and not any(
        base_domain == allowed or host == allowed or host.endswith(f".{allowed}")
        for allowed in ALLOWED_DOMAINS
    ):
        return None

    content_type = ""
    headers = getattr(response, "headers", {}) or {}
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            content_type = str(value)
            break

    raw_content = getattr(response, "content", None) or getattr(response, "raw_content", None) or b""
    is_textual = content_type.startswith("text/") or "json" in content_type or "javascript" in content_type
    snippet = None
    page_title = None
    if is_textual:
        body = raw_content[:SNIPPET_MAX_BYTES]
        snippet = body.decode("utf-8", errors="replace")
        page_title = extract_page_title(raw_content[:32768])

    url = getattr(request, "pretty_url", None) or getattr(request, "url", None) or ""
    content_category, content_id, search_query, service_name = extract_site_details(url, page_title)
    
    # Use Service Name for better visibility
    if not page_title:
        if content_id:
            page_title = f"{service_name}: {content_id}"
        elif search_query:
            page_title = f"Search: {search_query}"
        else:
            page_title = service_name if service_name != base_domain else split_url_label(url)

    request_headers = getattr(request, "headers", {}) or {}
    browser_name, process_name = infer_browser_identity(request_headers)

    return DpiObservation(
        browser_name=browser_name,
        process_name=process_name,
        page_url=url,
        base_domain=base_domain,
        page_title=page_title or "Untitled",
        content_category=content_category,
        content_id=content_id,
        search_query=search_query,
        http_method=getattr(request, "method", "GET"),
        status_code=getattr(response, "status_code", None),
        content_type=content_type or None,
        request_bytes=len(getattr(request, "raw_content", None) or b""),
        response_bytes=len(raw_content),
        snippet_redacted=snippet,
        timestamp=datetime.now(timezone.utc).isoformat(),
        app=browser_name,
    ).to_payload()


def split_url_label(url: str) -> str:
    split = urlsplit(url or "")
    if split.path and split.path != "/":
        return split.path.strip("/").replace("-", " ")[:255] or split.netloc
    return split.netloc or "Untitled"


def response(flow):
    event = build_event(flow)
    if event:
        print(f"{EVENT_PREFIX}{json.dumps(event, ensure_ascii=False)}", flush=True)
