from __future__ import annotations

import json
import os
import re
from html import unescape
from urllib.parse import parse_qs, urlsplit

from app.utils.domain_utils import get_base_domain, normalize_host

EVENT_PREFIX = "__NETVISOR_WEB_EVENT__"
ALLOWED_DOMAINS = {
    item
    for item in json.loads(os.getenv("NETVISOR_ALLOWED_DOMAINS_JSON", "[]") or "[]")
    if str(item).strip()
}
SNIPPET_MAX_BYTES = min(max(int(os.getenv("NETVISOR_SNIPPET_MAX_BYTES", "256")), 0), 256)


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


def extract_site_metadata(url: str, page_title: str | None) -> tuple[str, str | None]:
    split = urlsplit(url or "")
    base_domain = get_base_domain(split.netloc) or split.netloc
    query = parse_qs(split.query)

    if base_domain == "youtube.com":
        return "video", (query.get("v") or [None])[0]
    if base_domain == "googlevideo.com":
        return "video-stream", (query.get("id") or [None])[0]
    if base_domain in {"openai.com", "chatgpt.com"}:
        return "chat", None
    if base_domain == "github.com":
        path = split.path.strip("/").split("/")
        if len(path) >= 2:
            return "repository", "/".join(path[:2])
    return "web", None


def build_event(flow) -> dict | None:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    if not request or not response:
        return None

    host = normalize_host(getattr(request, "pretty_host", None) or getattr(request, "host", None))
    base_domain = get_base_domain(host) or host
    if not base_domain or (ALLOWED_DOMAINS and base_domain not in ALLOWED_DOMAINS):
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
    content_category, content_id = extract_site_metadata(url, page_title)
    if not page_title:
        page_title = content_id or split_url_label(url)

    user_agent = ""
    request_headers = getattr(request, "headers", {}) or {}
    for key, value in request_headers.items():
        if str(key).lower() == "user-agent":
            user_agent = str(value)
            break

    browser_name = "Unknown"
    lowered_user_agent = user_agent.lower()
    if "edg/" in lowered_user_agent:
        browser_name = "Edge"
    elif "chrome/" in lowered_user_agent:
        browser_name = "Chrome"

    process_name = "unknown"
    if browser_name == "Chrome":
        process_name = "chrome.exe"
    elif browser_name == "Edge":
        process_name = "msedge.exe"

    return {
        "browser_name": browser_name,
        "process_name": process_name,
        "page_url": url,
        "base_domain": base_domain,
        "page_title": page_title or "Untitled",
        "content_category": content_category,
        "content_id": content_id,
        "http_method": getattr(request, "method", "GET"),
        "status_code": getattr(response, "status_code", None),
        "content_type": content_type or None,
        "request_bytes": len(getattr(request, "raw_content", None) or b""),
        "response_bytes": len(raw_content),
        "snippet_redacted": snippet,
        "headers": dict(request_headers.items()) if hasattr(request_headers, "items") else {},
    }


def split_url_label(url: str) -> str:
    split = urlsplit(url or "")
    if split.path and split.path != "/":
        return split.path.strip("/").replace("-", " ")[:255] or split.netloc
    return split.netloc or "Untitled"


def response(flow):
    event = build_event(flow)
    if event:
        print(f"{EVENT_PREFIX}{json.dumps(event, ensure_ascii=False)}", flush=True)
