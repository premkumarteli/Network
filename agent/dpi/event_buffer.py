from __future__ import annotations

import logging
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Callable

import requests

from app.utils.domain_utils import get_base_domain, normalize_host

from .policy import InspectionPolicy
from .redaction import hash_text, redact_headers, redact_url, sanitize_text_snippet

logger = logging.getLogger(__name__)


class EventBuffer:
    def __init__(
        self,
        *,
        upload_url: str,
        headers: dict,
        get_policy: Callable[[], InspectionPolicy],
        get_context: Callable[[], dict],
    ) -> None:
        self.upload_url = upload_url
        self.headers = headers
        self.get_policy = get_policy
        self.get_context = get_context
        self.queue: queue.Queue = queue.Queue(maxsize=5000)
        self._running = False
        self._worker: threading.Thread | None = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._worker = threading.Thread(target=self._upload_worker, daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._running = False

    def enqueue(self, event: dict) -> None:
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            logger.warning("Dropping web inspection event because the queue is full.")

    def _prepare_event(self, raw_event: dict) -> dict | None:
        policy = self.get_policy()
        context = self.get_context()

        domain = get_base_domain(raw_event.get("base_domain") or raw_event.get("page_url") or "") or normalize_host(
            raw_event.get("base_domain")
        )
        process_name = str(raw_event.get("process_name") or "unknown").lower()
        if not policy.inspection_enabled or not policy.allows_domain(domain):
            return None
        if not policy.allows_process(process_name):
            return None

        snippet = sanitize_text_snippet(raw_event.get("snippet_redacted"), max_bytes=policy.snippet_max_bytes)
        browser_name = raw_event.get("browser_name") or ("Edge" if "msedge" in process_name else "Chrome" if "chrome" in process_name else "Unknown")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "organization_id": context.get("organization_id"),
            "agent_id": context.get("agent_id"),
            "device_ip": context.get("device_ip"),
            "process_name": process_name,
            "browser_name": browser_name,
            "page_url": redact_url(raw_event.get("page_url") or ""),
            "base_domain": domain or normalize_host(raw_event.get("base_domain")) or "-",
            "page_title": str(raw_event.get("page_title") or "Untitled")[:255],
            "content_category": str(raw_event.get("content_category") or "web")[:100],
            "content_id": raw_event.get("content_id"),
            "http_method": str(raw_event.get("http_method") or "GET")[:16],
            "status_code": raw_event.get("status_code"),
            "content_type": raw_event.get("content_type"),
            "request_bytes": int(raw_event.get("request_bytes") or 0),
            "response_bytes": int(raw_event.get("response_bytes") or 0),
            "snippet_redacted": snippet,
            "snippet_hash": hash_text(snippet),
            "first_seen": raw_event.get("first_seen") or now,
            "last_seen": raw_event.get("last_seen") or now,
            "headers_redacted": redact_headers(raw_event.get("headers") or {}),
        }

    def _upload_worker(self) -> None:
        batch = []
        last_send = time.time()

        while self._running:
            try:
                try:
                    item = self.queue.get(timeout=1.0)
                    prepared = self._prepare_event(item)
                    if prepared:
                        batch.append(prepared)
                    self.queue.task_done()
                except queue.Empty:
                    pass

                if batch and (len(batch) >= 20 or time.time() - last_send >= 3):
                    payload = [
                        {
                            key: value
                            for key, value in item.items()
                            if key != "headers_redacted"
                        }
                        for item in batch
                    ]
                    response = requests.post(
                        self.upload_url,
                        json=payload,
                        headers=self.headers,
                        timeout=10,
                    )
                    response.raise_for_status()
                    batch = []
                    last_send = time.time()
            except Exception as exc:
                logger.warning("Web inspection upload failed: %s", exc)
                time.sleep(2)
