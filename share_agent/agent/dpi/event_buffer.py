from __future__ import annotations

import json
import logging
import queue
import threading
import time
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from shared.intel import get_base_domain, normalize_host

from .policy import InspectionPolicy
from .redaction import hash_text, redact_headers, redact_url, sanitize_text_snippet
from ..security import AgentApiClient, DataProtector, WindowsCurrentUserProtector

logger = logging.getLogger(__name__)


def _normalize_browser_label(browser_name: str | None, process_name: str | None) -> tuple[str, str]:
    process = str(process_name or "").strip().lower()
    browser = str(browser_name or "").strip()
    lowered_browser = browser.lower()

    if process in {"msedge.exe", "edge.exe"} or "edge" in lowered_browser or "edg" in lowered_browser:
        return "Edge", "msedge.exe"
    if process in {"chrome.exe", "chromium.exe"} or "chrome" in lowered_browser or "chromium" in lowered_browser:
        return "Chrome", "chrome.exe"
    if process == "firefox.exe" or "firefox" in lowered_browser:
        return "Firefox", "firefox.exe"
    if process == "safari.exe" or ("safari" in lowered_browser and "chrome" not in lowered_browser):
        return "Safari", "safari.exe"
    if process == "python.exe" or "python" in lowered_browser:
        return "Python", "python.exe"
    return (browser or "Unknown"), (process or "unknown")


def _preferred_domain_label(value: str | None) -> str | None:
    host = normalize_host(value)
    if not host:
        return None
    base_domain = get_base_domain(host) or host
    return host if host != base_domain else base_domain


class EventBuffer:
    def __init__(
        self,
        *,
        runtime_dir: Path,
        upload_url: str,
        api_client: AgentApiClient,
        get_policy: Callable[[], InspectionPolicy],
        get_context: Callable[[], dict],
        protector: DataProtector | None = None,
    ) -> None:
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.spool_dir = self.runtime_dir / "spool"
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.spool_file = self.spool_dir / "web_events.spool.dpapi"

        self.upload_url = upload_url
        self.api_client = api_client
        self.get_policy = get_policy
        self.get_context = get_context
        self.protector = protector or WindowsCurrentUserProtector()
        self.queue: queue.Queue = queue.Queue(maxsize=5000)
        self._running = False
        self._worker: threading.Thread | None = None
        self._spool_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._metrics = {
            "last_event_at": None,
            "last_upload_at": None,
            "last_spool_at": None,
            "spooled_event_count": 0,
            "dropped_event_count": 0,
            "uploaded_event_count": 0,
            "upload_failures": 0,
            "last_drop_reason": None,
            "drop_reasons": {},
        }

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._refresh_spool_count()
        self._worker = threading.Thread(target=self._upload_worker, daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._running = False
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=2.0)

    def enqueue(self, event: dict) -> None:
        self._set_metric(last_event_at=self._utc_now())
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            prepared = self._prepare_event(event)
            if prepared:
                self._spool_events([prepared], reason="queue_full")
                logger.warning("Spooling web inspection event because the in-memory queue is full.")

    def _set_metric(self, **updates) -> None:
        with self._metrics_lock:
            for key, value in updates.items():
                if key == "drop_reasons" and isinstance(value, dict):
                    self._metrics[key] = dict(value)
                else:
                    self._metrics[key] = value

    def _increment_metric(self, key: str, amount: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[key] = int(self._metrics.get(key) or 0) + amount

    def _record_drop(self, reason: str) -> None:
        with self._metrics_lock:
            drop_reasons = dict(self._metrics.get("drop_reasons") or {})
            drop_reasons[reason] = int(drop_reasons.get(reason) or 0) + 1
            self._metrics["drop_reasons"] = drop_reasons
            self._metrics["dropped_event_count"] = int(self._metrics.get("dropped_event_count") or 0) + 1
            self._metrics["last_drop_reason"] = reason

    def _refresh_spool_count(self) -> int:
        count = 0
        if self.spool_file.exists():
            try:
                with self.spool_file.open("r", encoding="utf-8") as handle:
                    count = sum(1 for line in handle if line.strip())
            except OSError:
                count = 0
        self._set_metric(spooled_event_count=count)
        return count

    def _confidence_for_event(self, raw_event: dict, *, domain: str, snippet: str | None) -> tuple[float, str]:
        score = 0.0
        if domain:
            score += 0.35
        title = str(raw_event.get("page_title") or "").strip()
        if title and title.lower() != "untitled":
            score += 0.35
        if raw_event.get("content_id"):
            score += 0.2
        if raw_event.get("search_query"):
            score += 0.05
        if snippet:
            score += 0.05
        score = round(min(max(score, 0.0), 1.0), 2)
        if score >= 0.8:
            return score, "High"
        if score >= 0.55:
            return score, "Medium"
        return score, "Low"

    def _prepare_event(self, raw_event: dict) -> dict | None:
        policy = self.get_policy()
        context = self.get_context()

        preferred_domain = (
            _preferred_domain_label(raw_event.get("base_domain"))
            or _preferred_domain_label(raw_event.get("page_url"))
        )
        domain = preferred_domain or get_base_domain(raw_event.get("page_url") or "") or normalize_host(
            raw_event.get("base_domain")
        )
        browser_name, process_name = _normalize_browser_label(
            raw_event.get("browser_name"),
            raw_event.get("process_name"),
        )

        if not policy.inspection_enabled:
            self._record_drop("inspection_disabled")
            logger.debug("DPI event dropped: Inspection disabled")
            return None
        if policy.should_bypass_sensitive_destination(domain):
            self._record_drop("sensitive_destination_bypassed")
            logger.debug("DPI event bypassed for sensitive destination '%s'", domain)
            return None
        if not policy.allows_domain(domain):
            self._record_drop("domain_not_allowed")
            logger.debug("DPI event dropped: Domain '%s' not allowed by policy", domain)
            return None
        if not policy.allows_process(process_name):
            self._record_drop("process_not_allowed")
            logger.debug("DPI event dropped: Process '%s' not allowed by policy", process_name)
            return None

        snippet = sanitize_text_snippet(raw_event.get("snippet_redacted"), max_bytes=policy.snippet_max_bytes)
        confidence_score, confidence_label = self._confidence_for_event(raw_event, domain=domain or "", snippet=snippet)
        now = self._utc_now()

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
            "search_query": str(raw_event.get("search_query") or "")[:255] or None,
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
            "confidence_score": confidence_score,
            "confidence_label": confidence_label,
        }

    def _spool_events(self, events: list[dict], *, reason: str) -> None:
        if not events:
            return
        with self._spool_lock:
            with self.spool_file.open("a", encoding="utf-8") as handle:
                for event in events:
                    payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                    protected = self.protector.protect(payload, description="netvisor-web-event")
                    handle.write(base64.b64encode(protected).decode("ascii") + "\n")
        self._set_metric(last_spool_at=self._utc_now())
        self._increment_metric("spooled_event_count", len(events))
        logger.info("Spooled %d web event(s) locally because %s.", len(events), reason)

    def _pull_spooled_events(self, limit: int) -> list[dict]:
        if limit <= 0 or not self.spool_file.exists():
            return []

        with self._spool_lock:
            try:
                with self.spool_file.open("r", encoding="utf-8") as handle:
                    lines = [line.strip() for line in handle if line.strip()]
            except OSError:
                return []

            if not lines:
                self._set_metric(spooled_event_count=0)
                return []

            selected = lines[:limit]
            remaining = lines[limit:]
            try:
                if remaining:
                    with self.spool_file.open("w", encoding="utf-8") as handle:
                        handle.write("\n".join(remaining) + "\n")
                else:
                    self.spool_file.unlink(missing_ok=True)
            except OSError:
                pass

        events: list[dict] = []
        for line in selected:
            try:
                decoded = base64.b64decode(line.encode("ascii"), validate=True)
                payload = self.protector.unprotect(decoded)
                events.append(json.loads(payload.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                self._record_drop("invalid_spool_payload")

        self._set_metric(spooled_event_count=max(len(remaining), 0))
        return events

    def _upload_batch(self, batch: list[dict]) -> None:
        payload = [{key: value for key, value in item.items() if key != "headers_redacted"} for item in batch]
        response = self.api_client.request("POST", self.upload_url, json_body=payload, timeout=10)
        response.raise_for_status()

    def _upload_worker(self) -> None:
        batch: list[dict] = []
        last_send = time.time()

        while self._running or not self.queue.empty() or batch:
            try:
                try:
                    item = self.queue.get(timeout=1.0)
                    prepared = self._prepare_event(item)
                    if prepared:
                        batch.append(prepared)
                    self.queue.task_done()
                except queue.Empty:
                    pass

                if len(batch) < 20:
                    batch.extend(self._pull_spooled_events(20 - len(batch)))

                if batch and (len(batch) >= 20 or time.time() - last_send >= 3 or not self._running):
                    try:
                        self._upload_batch(batch)
                        self._set_metric(last_upload_at=self._utc_now())
                        self._increment_metric("uploaded_event_count", len(batch))
                        logger.info("Successfully uploaded batch of %d DPI events", len(batch))
                        batch = []
                        last_send = time.time()
                    except Exception as exc:
                        self._increment_metric("upload_failures", 1)
                        self._spool_events(batch, reason="upload_failed")
                        logger.warning("Web inspection upload failed: %s", exc)
                        batch = []
                        time.sleep(2)
            except Exception as exc:
                logger.warning("Web inspection upload worker error: %s", exc)
                time.sleep(1)

    def metrics_snapshot(self) -> dict:
        with self._metrics_lock:
            snapshot = {
                "last_event_at": self._metrics.get("last_event_at"),
                "last_upload_at": self._metrics.get("last_upload_at"),
                "last_spool_at": self._metrics.get("last_spool_at"),
                "spooled_event_count": int(self._metrics.get("spooled_event_count") or 0),
                "dropped_event_count": int(self._metrics.get("dropped_event_count") or 0),
                "uploaded_event_count": int(self._metrics.get("uploaded_event_count") or 0),
                "upload_failures": int(self._metrics.get("upload_failures") or 0),
                "last_drop_reason": self._metrics.get("last_drop_reason"),
                "drop_reasons": dict(self._metrics.get("drop_reasons") or {}),
            }
        snapshot["queue_size"] = self.queue.qsize()
        return snapshot
