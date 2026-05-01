from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..core.config import settings
from ..db.session import require_runtime_schema
from ..utils.domain_intelligence import classify_domain, get_service_info, is_noise, is_sensitive_destination
from ..utils.domain_utils import get_base_domain, normalize_host
from .threat_intelligence_service import threat_intel

logger = logging.getLogger("netvisor.web_inspection")


class WebInspectionService:
    DEFAULT_ALLOWED_PROCESSES = ["chrome.exe", "msedge.exe"]
    DEFAULT_ALLOWED_DOMAINS = [
        "youtube.com",
        "googlevideo.com",
        "youtubei.googleapis.com",
        "google.com",
        "bing.com",
        "duckduckgo.com",
        "search.brave.com",
        "openai.com",
        "chatgpt.com",
        "anthropic.com",
        "claude.ai",
        "gemini.google.com",
        "copilot.microsoft.com",
        "perplexity.ai",
        "github.com",
        "githubassets.com",
        "githubusercontent.com",
    ]
    LEGACY_ALLOWED_DOMAINS = [
        "youtube.com",
        "googlevideo.com",
        "youtubei.googleapis.com",
        "openai.com",
        "chatgpt.com",
        "github.com",
        "githubassets.com",
        "githubusercontent.com",
    ]
    DEFAULT_SNIPPET_MAX_BYTES = 256
    EVENT_RETENTION_HOURS = 24

    def __init__(self) -> None:
        self._schema_ready = False

    def _index_exists(self, cursor, table_name: str, index_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = %s AND table_name = %s AND index_name = %s
            LIMIT 1
            """,
            (settings.DB_NAME, table_name, index_name),
        )
        return cursor.fetchone() is not None

    def _normalize_processes(self, values: list[str] | None) -> list[str]:
        normalized = []
        for value in values or []:
            item = str(value or "").strip().lower()
            if item and item not in normalized:
                normalized.append(item)
        return normalized

    def _normalize_domains(self, values: list[str] | None) -> list[str]:
        normalized = []
        for value in values or []:
            host = normalize_host(value)
            if not host:
                continue
            if host not in normalized:
                normalized.append(host)
        return normalized

    def _resolve_allowed_domains(self, values: list[str] | None) -> list[str]:
        normalized = self._normalize_domains(values)
        if not normalized:
            return list(self.DEFAULT_ALLOWED_DOMAINS)
        if set(normalized) == set(self.LEGACY_ALLOWED_DOMAINS):
            return list(self.DEFAULT_ALLOWED_DOMAINS)
        return normalized

    def _json_dumps(self, value: Any) -> str:
        return json.dumps(value or [])

    def _json_loads(self, value: Any, default):
        if value in (None, "", b""):
            return default
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return default
        return parsed if isinstance(parsed, type(default)) else default

    def _format_timestamp(self, value) -> Optional[str]:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value) if value else None

    def _parse_timestamp(self, value) -> Optional[datetime]:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                return None
        return None

    def _normalize_risk_level(self, value) -> str:
        normalized = str(value or "safe").strip().lower()
        if normalized in {"safe", "low"}:
            return "safe"
        if normalized in {"medium", "yellow", "warning"}:
            return "medium"
        if normalized in {"high", "red", "danger"}:
            return "high"
        if normalized == "critical":
            return "critical"
        return "safe"

    def _risk_rank(self, value) -> int:
        return {
            "safe": 0,
            "medium": 1,
            "high": 2,
            "critical": 3,
        }.get(self._normalize_risk_level(value), 0)

    def _append_unique(self, target: list[str], value: Any) -> None:
        if value is None:
            return
        item = str(value).strip()
        if item and item not in target:
            target.append(item)

    def _is_generic_page_title(self, value: Optional[str]) -> bool:
        normalized = str(value or "").strip().lower()
        return normalized in {
            "",
            "untitled",
            "untitled page",
            "new tab",
            "new tab page",
            "browser",
            "about:blank",
        }

    def _build_group_label(self, row: dict) -> str:
        page_title = str(row.get("page_title") or "").strip()
        if page_title and not self._is_generic_page_title(page_title):
            return page_title
        content_id = str(row.get("content_id") or "").strip()
        if content_id:
            return content_id
        base_domain = str(row.get("base_domain") or "").strip()
        if base_domain:
            return base_domain
        page_url = str(row.get("page_url") or "").strip()
        if page_url:
            return page_url
        return "Browser Evidence"

    def _web_evidence_group_key(self, row: dict) -> str:
        device_ip = str(row.get("device_ip") or "").strip().lower()
        browser_name = str(row.get("browser_name") or "Unknown").strip().lower()
        process_name = str(row.get("process_name") or "unknown").strip().lower()
        content_id = str(row.get("content_id") or "").strip().lower()
        page_url = str(row.get("page_url") or "").strip().lower()
        base_domain = str(row.get("base_domain") or "").strip().lower()
        page_title = str(row.get("page_title") or "").strip().lower()
        tab_key = content_id or page_url or (f"{base_domain}|{page_title}" if base_domain or page_title else "") or base_domain or page_title or "unknown"
        return f"{device_ip}|{browser_name}|{process_name}|{tab_key}"

    def _load_web_events(
        self,
        db_conn,
        *,
        device_ip: Optional[str],
        organization_id: Optional[str],
        limit: int,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        self.purge_expired_events(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            if device_ip:
                cursor.execute(
                    """
                    SELECT
                        id, agent_id, device_ip, process_name, browser_name, page_url, base_domain,
                        page_title, content_category, content_id, search_query, http_method,
                        status_code, content_type, request_bytes, response_bytes,
                        snippet_redacted, snippet_hash, confidence_score, event_count,
                        risk_level, threat_msg, first_seen, last_seen
                    FROM web_events
                    WHERE device_ip = %s
                      AND (%s IS NULL OR organization_id = %s OR organization_id IS NULL)
                    ORDER BY last_seen DESC, id DESC
                    LIMIT %s
                    """,
                    (device_ip, organization_id, organization_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT
                        id, agent_id, device_ip, process_name, browser_name, page_url, base_domain,
                        page_title, content_category, content_id, search_query, http_method,
                        status_code, content_type, request_bytes, response_bytes,
                        snippet_redacted, snippet_hash, confidence_score, event_count,
                        risk_level, threat_msg, first_seen, last_seen
                    FROM web_events
                    WHERE base_domain IS NOT NULL AND base_domain != ''
                      AND (%s IS NULL OR organization_id = %s OR organization_id IS NULL)
                    ORDER BY last_seen DESC, id DESC
                    LIMIT %s
                    """,
                    (organization_id, organization_id, limit),
                )
            return cursor.fetchall()
        finally:
            cursor.close()

    def _normalize_activity_row(self, row: dict) -> dict:
        first_seen = self._parse_timestamp(row.get("first_seen")) or self._parse_timestamp(row.get("last_seen")) or datetime.now(timezone.utc)
        last_seen = self._parse_timestamp(row.get("last_seen")) or first_seen
        return {
            "id": row.get("id"),
            "agent_id": str(row.get("agent_id") or "").strip() or None,
            "device_ip": str(row.get("device_ip") or "").strip() or None,
            "process_name": str(row.get("process_name") or "unknown").strip() or "unknown",
            "browser_name": str(row.get("browser_name") or "Unknown").strip() or "Unknown",
            "page_url": str(row.get("page_url") or "").strip() or None,
            "base_domain": str(row.get("base_domain") or "").strip() or None,
            "page_title": str(row.get("page_title") or "Untitled").strip() or "Untitled",
            "content_category": str(row.get("content_category") or "web").strip() or "web",
            "content_id": str(row.get("content_id") or "").strip() or None,
            "search_query": str(row.get("search_query") or "").strip() or None,
            "http_method": str(row.get("http_method") or "GET").strip() or "GET",
            "status_code": int(row.get("status_code")) if row.get("status_code") not in (None, "") else None,
            "content_type": str(row.get("content_type") or "").strip() or None,
            "request_bytes": max(int(row.get("request_bytes") or 0), 0),
            "response_bytes": max(int(row.get("response_bytes") or 0), 0),
            "snippet_redacted": row.get("snippet_redacted"),
            "snippet_hash": str(row.get("snippet_hash") or "").strip() or None,
            "event_count": max(int(row.get("event_count") or 1), 1),
            "risk_level": self._normalize_risk_level(row.get("risk_level")),
            "threat_msg": row.get("threat_msg"),
            "confidence_score": max(min(float(row.get("confidence_score") or 0.0), 1.0), 0.0),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    def _activity_record(self, row: dict, *, include_identity: bool) -> dict:
        normalized = self._normalize_activity_row(row)
        record = {
            "page_url": normalized["page_url"] or normalized["base_domain"] or normalized["page_title"] or "",
            "base_domain": normalized["base_domain"] or "",
            "page_title": normalized["page_title"],
            "browser_name": normalized["browser_name"],
            "process_name": normalized["process_name"],
            "content_category": normalized["content_category"],
            "content_id": normalized["content_id"],
            "search_query": normalized["search_query"],
            "http_method": normalized["http_method"],
            "status_code": normalized["status_code"],
            "content_type": normalized["content_type"],
            "request_bytes": normalized["request_bytes"],
            "response_bytes": normalized["response_bytes"],
            "snippet_redacted": normalized["snippet_redacted"],
            "snippet_hash": normalized["snippet_hash"],
            "event_count": normalized["event_count"],
            "risk_level": normalized["risk_level"],
            "threat_msg": normalized["threat_msg"],
            "confidence_score": normalized["confidence_score"],
            "first_seen": self._format_timestamp(normalized["first_seen"]),
            "last_seen": self._format_timestamp(normalized["last_seen"]),
        }
        if include_identity:
            record["agent_id"] = normalized["agent_id"]
            record["device_ip"] = normalized["device_ip"]
        return record

    def _group_activity_rows(self, rows: list[dict]) -> list[dict]:
        groups: dict[str, dict] = {}
        for row in rows:
            normalized = self._normalize_activity_row(row)
            group_key = self._web_evidence_group_key(normalized)
            group = groups.get(group_key)
            if not group:
                group = {
                    "group_key": group_key,
                    "group_label": self._build_group_label(normalized),
                    "agent_id": normalized["agent_id"],
                    "device_ip": normalized["device_ip"],
                    "browser_name": normalized["browser_name"],
                    "process_name": normalized["process_name"],
                    "base_domain": normalized["base_domain"],
                    "page_url": normalized["page_url"],
                    "page_title": normalized["page_title"],
                    "content_category": normalized["content_category"],
                    "content_id": normalized["content_id"],
                    "search_query": normalized["search_query"],
                    "http_method": normalized["http_method"],
                    "status_code": normalized["status_code"],
                    "content_type": normalized["content_type"],
                    "request_bytes": 0,
                    "response_bytes": 0,
                    "snippet_redacted": normalized["snippet_redacted"],
                    "snippet_hash": normalized["snippet_hash"],
                    "event_count": 0,
                    "risk_level": normalized["risk_level"],
                    "threat_msg": normalized["threat_msg"],
                    "confidence_score": normalized["confidence_score"],
                    "_first_seen": normalized["first_seen"],
                    "_last_seen": normalized["last_seen"],
                    "page_urls": [],
                    "page_titles": [],
                    "content_ids": [],
                    "search_queries": [],
                }
                groups[group_key] = group

            group["request_bytes"] += normalized["request_bytes"]
            group["response_bytes"] += normalized["response_bytes"]
            group["event_count"] += normalized["event_count"]
            group["confidence_score"] = max(group["confidence_score"], normalized["confidence_score"])

            if normalized["first_seen"] and (group.get("_first_seen") is None or normalized["first_seen"] < group["_first_seen"]):
                group["_first_seen"] = normalized["first_seen"]
            if normalized["last_seen"] and (group.get("_last_seen") is None or normalized["last_seen"] > group["_last_seen"]):
                group["_last_seen"] = normalized["last_seen"]
                for field in (
                    "agent_id",
                    "device_ip",
                    "browser_name",
                    "process_name",
                    "base_domain",
                    "page_url",
                    "page_title",
                    "content_category",
                    "content_id",
                    "search_query",
                    "http_method",
                    "status_code",
                    "content_type",
                    "snippet_redacted",
                    "snippet_hash",
                ):
                    value = normalized.get(field)
                    if value not in (None, ""):
                        group[field] = value
                group["group_label"] = self._build_group_label(normalized)

            if self._risk_rank(normalized["risk_level"]) > self._risk_rank(group["risk_level"]):
                group["risk_level"] = normalized["risk_level"]
                group["threat_msg"] = normalized["threat_msg"]
            elif self._risk_rank(normalized["risk_level"]) == self._risk_rank(group["risk_level"]) and normalized["threat_msg"] and not group.get("threat_msg"):
                group["threat_msg"] = normalized["threat_msg"]

            self._append_unique(group["page_urls"], normalized["page_url"])
            self._append_unique(group["page_titles"], normalized["page_title"])
            self._append_unique(group["content_ids"], normalized["content_id"])
            self._append_unique(group["search_queries"], normalized["search_query"])
            if normalized["snippet_redacted"] and not group.get("snippet_redacted"):
                group["snippet_redacted"] = normalized["snippet_redacted"]
            if normalized["snippet_hash"] and not group.get("snippet_hash"):
                group["snippet_hash"] = normalized["snippet_hash"]

        ordered_groups = sorted(
            groups.values(),
            key=lambda item: (
                item.get("_last_seen") or datetime.min.replace(tzinfo=timezone.utc),
                item.get("event_count") or 0,
            ),
            reverse=True,
        )

        results = []
        for group in ordered_groups:
            results.append(
                {
                    "group_key": group["group_key"],
                    "group_label": group["group_label"],
                    "agent_id": group.get("agent_id"),
                    "device_ip": group.get("device_ip"),
                    "browser_name": group.get("browser_name") or "Unknown",
                    "process_name": group.get("process_name") or "unknown",
                    "page_url": group.get("page_url") or group.get("base_domain") or group.get("page_title") or "",
                    "base_domain": group.get("base_domain") or "",
                    "page_title": group.get("page_title") or "Untitled",
                    "content_category": group.get("content_category") or "web",
                    "content_id": group.get("content_id"),
                    "search_query": group.get("search_query"),
                    "http_method": group.get("http_method") or "GET",
                    "status_code": group.get("status_code"),
                    "content_type": group.get("content_type"),
                    "request_bytes": int(group.get("request_bytes") or 0),
                    "response_bytes": int(group.get("response_bytes") or 0),
                    "snippet_redacted": group.get("snippet_redacted"),
                    "snippet_hash": group.get("snippet_hash"),
                    "event_count": int(group.get("event_count") or 0),
                    "risk_level": group.get("risk_level") or "safe",
                    "threat_msg": group.get("threat_msg"),
                    "confidence_score": float(group.get("confidence_score") or 0.0),
                    "first_seen": self._format_timestamp(group.get("_first_seen")),
                    "last_seen": self._format_timestamp(group.get("_last_seen")),
                    "page_urls": list(group.get("page_urls") or []),
                    "page_titles": list(group.get("page_titles") or []),
                    "content_ids": list(group.get("content_ids") or []),
                    "search_queries": list(group.get("search_queries") or []),
                }
            )
        return results

    def _default_policy(self, agent_id: Optional[str], device_ip: str) -> dict:
        return {
            "agent_id": agent_id,
            "device_ip": device_ip,
            "inspection_enabled": False,
            "allowed_processes": list(self.DEFAULT_ALLOWED_PROCESSES),
            "allowed_domains": list(self.DEFAULT_ALLOWED_DOMAINS),
            "snippet_max_bytes": self.DEFAULT_SNIPPET_MAX_BYTES,
            "privacy_guard_enabled": True,
            "sensitive_destination_bypass_enabled": True,
            "updated_at": None,
        }

    def _column_exists(self, cursor, table_name: str, column_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s AND column_name = %s
            LIMIT 1
            """,
            (settings.DB_NAME, table_name, column_name),
        )
        return cursor.fetchone() is not None

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def purge_expired_events(self, db_conn) -> int:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                DELETE FROM web_events
                WHERE COALESCE(last_seen, created_at) < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)
                """,
                (self.EVENT_RETENTION_HOURS,),
            )
            deleted = cursor.rowcount
            db_conn.commit()
            return max(int(deleted or 0), 0)
        finally:
            cursor.close()

    def get_policy(
        self,
        db_conn,
        *,
        agent_id: Optional[str],
        device_ip: str,
        organization_id: Optional[str] = None,
    ) -> dict:
        self.ensure_schema(db_conn)
        default_policy = self._default_policy(agent_id, device_ip)
        if not agent_id or not device_ip:
            return default_policy

        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT *
                FROM inspection_policies
                WHERE agent_id = %s AND device_ip = %s
                LIMIT 1
                """,
                (agent_id, device_ip),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()

        if not row:
            return default_policy

        return {
            "agent_id": row.get("agent_id") or agent_id,
            "device_ip": row.get("device_ip") or device_ip,
            "inspection_enabled": bool(row.get("inspection_enabled")),
            "allowed_processes": self._normalize_processes(
                self._json_loads(row.get("allowed_processes_json"), list(self.DEFAULT_ALLOWED_PROCESSES))
            ),
            "allowed_domains": self._resolve_allowed_domains(
                self._json_loads(row.get("allowed_domains_json"), list(self.DEFAULT_ALLOWED_DOMAINS))
            ),
            "snippet_max_bytes": min(
                max(int(row.get("snippet_max_bytes") or self.DEFAULT_SNIPPET_MAX_BYTES), 0),
                self.DEFAULT_SNIPPET_MAX_BYTES,
            ),
            "privacy_guard_enabled": True,
            "sensitive_destination_bypass_enabled": True,
            "updated_at": self._format_timestamp(row.get("updated_at")),
            "organization_id": row.get("organization_id") or organization_id,
        }

    def set_policy(
        self,
        db_conn,
        *,
        agent_id: str,
        device_ip: str,
        organization_id: Optional[str],
        inspection_enabled: Optional[bool] = None,
        allowed_processes: Optional[list[str]] = None,
        allowed_domains: Optional[list[str]] = None,
        snippet_max_bytes: Optional[int] = None,
    ) -> dict:
        self.ensure_schema(db_conn)
        current = self.get_policy(
            db_conn,
            agent_id=agent_id,
            device_ip=device_ip,
            organization_id=organization_id,
        )
        merged = {
            "inspection_enabled": current["inspection_enabled"] if inspection_enabled is None else bool(inspection_enabled),
            "allowed_processes": self._normalize_processes(
                allowed_processes if allowed_processes is not None else current["allowed_processes"]
            ) or list(self.DEFAULT_ALLOWED_PROCESSES),
            "allowed_domains": self._resolve_allowed_domains(
                allowed_domains if allowed_domains is not None else current["allowed_domains"]
            ) or list(self.DEFAULT_ALLOWED_DOMAINS),
            "snippet_max_bytes": min(
                max(
                    int(
                        current["snippet_max_bytes"]
                        if snippet_max_bytes is None
                        else snippet_max_bytes
                    ),
                    0,
                ),
                self.DEFAULT_SNIPPET_MAX_BYTES,
            ),
            "privacy_guard_enabled": True,
            "sensitive_destination_bypass_enabled": True,
        }

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO inspection_policies (
                    agent_id,
                    device_ip,
                    organization_id,
                    inspection_enabled,
                    allowed_processes_json,
                    allowed_domains_json,
                    snippet_max_bytes
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    organization_id = VALUES(organization_id),
                    inspection_enabled = VALUES(inspection_enabled),
                    allowed_processes_json = VALUES(allowed_processes_json),
                    allowed_domains_json = VALUES(allowed_domains_json),
                    snippet_max_bytes = VALUES(snippet_max_bytes),
                    updated_at = UTC_TIMESTAMP()
                """,
                (
                    agent_id,
                    device_ip,
                    organization_id,
                    merged["inspection_enabled"],
                    self._json_dumps(merged["allowed_processes"]),
                    self._json_dumps(merged["allowed_domains"]),
                    merged["snippet_max_bytes"],
                ),
            )
            db_conn.commit()
        finally:
            cursor.close()

        return self.get_policy(
            db_conn,
            agent_id=agent_id,
            device_ip=device_ip,
            organization_id=organization_id,
        )

    def _resolve_device_mapping(self, db_conn, device_ip: str, organization_id: Optional[str]) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT
                    COALESCE(md.agent_id, d.agent_id) AS agent_id,
                    COALESCE(md.organization_id, d.organization_id) AS organization_id,
                    CASE
                        WHEN md.agent_id IS NOT NULL THEN 'managed'
                        ELSE COALESCE(NULLIF(d.agent_id, ''), NULL)
                    END AS source_hint
                FROM devices d
                LEFT JOIN managed_devices md
                    ON (
                        (NULLIF(d.mac, '') IS NOT NULL AND NULLIF(md.device_mac, '') IS NOT NULL AND d.mac = md.device_mac)
                        OR d.ip = md.device_ip
                    )
                    AND (md.organization_id = d.organization_id OR md.organization_id IS NULL)
                WHERE d.ip = %s
                  AND (%s IS NULL OR d.organization_id = %s OR d.organization_id IS NULL)
                ORDER BY d.last_seen DESC
                LIMIT 1
                """,
                (device_ip, organization_id, organization_id),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "agent_id": row.get("agent_id"),
                    "organization_id": row.get("organization_id") or organization_id,
                }

            cursor.execute(
                """
                SELECT agent_id, organization_id
                FROM managed_devices
                WHERE device_ip = %s
                  AND (%s IS NULL OR organization_id = %s OR organization_id IS NULL)
                ORDER BY last_seen DESC
                LIMIT 1
                """,
                (device_ip, organization_id, organization_id),
            )
            row = cursor.fetchone() or {}
            return {
                "agent_id": row.get("agent_id"),
                "organization_id": row.get("organization_id") or organization_id,
            }
        finally:
            cursor.close()

    def _coerce_event(self, event: dict) -> Optional[dict]:
        device_ip = str(event.get("device_ip") or "").strip()
        agent_id = str(event.get("agent_id") or "").strip()
        if not device_ip or not agent_id:
            return None

        base_domain = str(event.get("base_domain") or "")
        if is_noise(base_domain):
            return None
        if is_sensitive_destination(base_domain):
            return None

        service_name, content_category = get_service_info(base_domain)

        first_seen = self._parse_timestamp(event.get("first_seen")) or datetime.now(timezone.utc)
        last_seen = self._parse_timestamp(event.get("last_seen")) or first_seen
        organization_id = event.get("organization_id")
        
        return (
            organization_id,
            agent_id,
            device_ip,
            str(event.get("process_name") or "unknown"),
            str(event.get("browser_name") or "Unknown"),
            str(event.get("page_url") or ""),
            base_domain,
            str(event.get("page_title") or "Untitled")[:255],
            content_category,
            str(event.get("content_id") or "")[:255] or None,
            str(event.get("search_query") or "")[:255] or None,
            str(event.get("http_method") or "GET")[:16],
            int(event.get("status_code")) if event.get("status_code") not in (None, "") else None,
            str(event.get("content_type") or "")[:120] or None,
            max(int(event.get("request_bytes") or 0), 0),
            max(int(event.get("response_bytes") or 0), 0),
            event.get("snippet_redacted"),
            str(event.get("snippet_hash") or "")[:64] or None,
            max(min(float(event.get("confidence_score") or 0.0), 1.0), 0.0),
            first_seen.astimezone(timezone.utc).replace(tzinfo=None),
            last_seen.astimezone(timezone.utc).replace(tzinfo=None),
            self._normalize_risk_level(event.get("risk_level", "safe")),
            event.get("threat_msg"),
            service_name,
        )

    def _coerced_event_dict(self, event: dict) -> Optional[dict]:
        row = self._coerce_event(event)
        if not row:
            return None
        (
            organization_id,
            agent_id,
            device_ip,
            process_name,
            browser_name,
            page_url,
            base_domain,
            page_title,
            content_category,
            content_id,
            search_query,
            http_method,
            status_code,
            content_type,
            request_bytes,
            response_bytes,
            snippet_redacted,
            snippet_hash,
            confidence_score,
            first_seen,
            last_seen,
            risk_level,
            threat_msg,
            service_name,
        ) = row
        return {
            "organization_id": organization_id,
            "agent_id": agent_id,
            "device_ip": device_ip,
            "process_name": process_name,
            "browser_name": browser_name,
            "page_url": page_url,
            "base_domain": base_domain,
            "page_title": page_title,
            "content_category": content_category,
            "content_id": content_id,
            "search_query": search_query,
            "http_method": http_method,
            "status_code": status_code,
            "content_type": content_type,
            "request_bytes": request_bytes,
            "response_bytes": response_bytes,
            "snippet_redacted": snippet_redacted,
            "snippet_hash": snippet_hash,
            "confidence_score": confidence_score,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "risk_level": risk_level,
            "threat_msg": threat_msg,
            "service_name": service_name,
        }

    def store_events(self, db_conn, events: list[dict]) -> int:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor()
        try:
            stored_count = 0
            for event in events:
                # Calculate threat before coercion
                threat_info = threat_intel.check_threat(event)
                event["risk_level"] = threat_info["risk_level"]
                event["threat_msg"] = threat_info["threat_msg"]

                row = self._coerced_event_dict(event)
                if not row:
                    continue
                
                # Aggregation Logic: Check if a similar event exists within the last 60 seconds
                # Similarity criteria: (device_ip, base_domain, page_url, content_id or page_title)
                page_url = row["page_url"] or ""
                content_id = row["content_id"] or ""
                cursor.execute(
                    """
                    SELECT id, event_count 
                    FROM web_events 
                    WHERE device_ip = %s AND base_domain = %s AND page_url = %s
                      AND (
                        (NULLIF(content_id, '') IS NOT NULL AND content_id = %s)
                        OR (NULLIF(content_id, '') IS NULL AND page_title = %s)
                      )
                      AND last_seen > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 60 SECOND)
                    ORDER BY last_seen DESC
                    LIMIT 1
                    """,
                    (row["device_ip"], row["base_domain"], page_url, content_id, row["page_title"])
                )
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing record: increment count and update last_seen
                    cursor.execute(
                        """
                        UPDATE web_events 
                        SET event_count = event_count + 1, 
                            last_seen = %s,
                            request_bytes = request_bytes + %s,
                            response_bytes = response_bytes + %s,
                            confidence_score = GREATEST(COALESCE(confidence_score, 0), %s),
                            snippet_redacted = COALESCE(%s, snippet_redacted),
                            snippet_hash = COALESCE(%s, snippet_hash),
                            risk_level = %s,
                            threat_msg = %s
                        WHERE id = %s
                        """,
                        (
                            row["last_seen"],
                            row["request_bytes"],
                            row["response_bytes"],
                            row["confidence_score"],
                            row["snippet_redacted"],
                            row["snippet_hash"],
                            row["risk_level"],
                            row["threat_msg"],
                            existing[0],
                        )
                    )
                else:
                    # Insert new record
                    cursor.execute(
                        """
                        INSERT INTO web_events (
                            organization_id, agent_id, device_ip, process_name, browser_name,
                            page_url, base_domain, page_title, content_category, content_id,
                            search_query, http_method, status_code, content_type,
                            request_bytes, response_bytes, snippet_redacted, snippet_hash,
                            confidence_score, event_count, first_seen, last_seen, risk_level, threat_msg
                        ) VALUES (
                            %(organization_id)s, %(agent_id)s, %(device_ip)s, %(process_name)s, %(browser_name)s,
                            %(page_url)s, %(base_domain)s, %(page_title)s, %(content_category)s, %(content_id)s,
                            %(search_query)s, %(http_method)s, %(status_code)s, %(content_type)s,
                            %(request_bytes)s, %(response_bytes)s, %(snippet_redacted)s, %(snippet_hash)s,
                            %(confidence_score)s, 1, %(first_seen)s, %(last_seen)s, %(risk_level)s, %(threat_msg)s
                        )
                        """,
                        row
                    )
                stored_count += 1
            
            db_conn.commit()
            return stored_count
        finally:
            cursor.close()

    def get_device_activity(
        self,
        db_conn,
        *,
        device_ip: str,
        organization_id: Optional[str],
        limit: int = 25,
    ) -> list[dict]:
        rows = self._load_web_events(
            db_conn,
            device_ip=device_ip,
            organization_id=organization_id,
            limit=limit,
        )
        return [self._activity_record(row, include_identity=False) for row in rows]

    def get_global_activity(
        self,
        db_conn,
        *,
        organization_id: Optional[str],
        limit: int = 100,
    ) -> list[dict]:
        rows = self._load_web_events(
            db_conn,
            device_ip=None,
            organization_id=organization_id,
            limit=limit,
        )
        return [self._activity_record(row, include_identity=True) for row in rows]

    def get_device_evidence_groups(
        self,
        db_conn,
        *,
        device_ip: str,
        organization_id: Optional[str],
        limit: int = 25,
    ) -> list[dict]:
        raw_limit = min(max(limit * 5, limit), 500)
        rows = self._load_web_events(
            db_conn,
            device_ip=device_ip,
            organization_id=organization_id,
            limit=raw_limit,
        )
        groups = self._group_activity_rows(rows)
        return groups[:limit]

    def get_global_evidence_groups(
        self,
        db_conn,
        *,
        organization_id: Optional[str],
        limit: int = 100,
    ) -> list[dict]:
        raw_limit = min(max(limit * 5, limit), 500)
        rows = self._load_web_events(
            db_conn,
            device_ip=None,
            organization_id=organization_id,
            limit=raw_limit,
        )
        groups = self._group_activity_rows(rows)
        return groups[:limit]

    def get_device_status(
        self,
        db_conn,
        *,
        device_ip: str,
        organization_id: Optional[str],
    ) -> dict:
        self.ensure_schema(db_conn)
        self.purge_expired_events(db_conn)

        mapping = self._resolve_device_mapping(db_conn, device_ip, organization_id)
        agent_id = mapping.get("agent_id")
        org_id = mapping.get("organization_id") or organization_id
        policy = self.get_policy(db_conn, agent_id=agent_id, device_ip=device_ip, organization_id=org_id)

        cursor = db_conn.cursor(dictionary=True)
        try:
            recent_limit = datetime.now(timezone.utc) - timedelta(hours=self.EVENT_RETENTION_HOURS)
            cursor.execute(
                """
                SELECT
                    inspection_enabled,
                    inspection_status,
                    inspection_proxy_running,
                    inspection_ca_installed,
                    inspection_browsers_json,
                    inspection_last_error,
                    inspection_metrics_json
                FROM agents
                WHERE id = %s
                LIMIT 1
                """,
                (agent_id,),
            )
            agent_row = cursor.fetchone() or {}
            cursor.execute(
                """
                SELECT MAX(last_seen) AS last_event_at, COUNT(*) AS recent_event_count
                FROM web_events
                WHERE device_ip = %s
                  AND (%s IS NULL OR organization_id = %s OR organization_id IS NULL)
                  AND COALESCE(last_seen, created_at) >= %s
                """,
                (device_ip, org_id, org_id, recent_limit.astimezone(timezone.utc).replace(tzinfo=None)),
            )
            events_row = cursor.fetchone() or {}
        finally:
            cursor.close()

        browsers = self._json_loads(
            agent_row.get("inspection_browsers_json"),
            list(policy["allowed_processes"]),
        )
        metrics = self._json_loads(agent_row.get("inspection_metrics_json"), {})
        status = agent_row.get("inspection_status") or ("enabled" if policy["inspection_enabled"] else "disabled")

        return {
            "agent_id": agent_id,
            "device_ip": device_ip,
            "inspection_enabled": bool(policy["inspection_enabled"]),
            "allowed_processes": list(policy["allowed_processes"]),
            "allowed_domains": list(policy["allowed_domains"]),
            "snippet_max_bytes": int(policy["snippet_max_bytes"]),
            "privacy_guard_enabled": bool(policy.get("privacy_guard_enabled", True)),
            "sensitive_destination_bypass_enabled": bool(policy.get("sensitive_destination_bypass_enabled", True)),
            "updated_at": policy.get("updated_at"),
            "browser_support": browsers,
            "proxy_running": bool(agent_row.get("inspection_proxy_running")),
            "ca_installed": bool(agent_row.get("inspection_ca_installed")),
            "ca_status": metrics.get("ca_status") or ("installed" if agent_row.get("inspection_ca_installed") else "missing"),
            "thumbprint_sha256": metrics.get("thumbprint_sha256"),
            "issued_at": metrics.get("issued_at"),
            "expires_at": metrics.get("expires_at"),
            "rotation_due_at": metrics.get("rotation_due_at"),
            "days_until_expiry": metrics.get("days_until_expiry"),
            "days_until_rotation_due": metrics.get("days_until_rotation_due"),
            "expires_soon": bool(metrics.get("expires_soon")) if metrics.get("expires_soon") is not None else None,
            "rotation_due_soon": bool(metrics.get("rotation_due_soon")) if metrics.get("rotation_due_soon") is not None else None,
            "trust_store_match": bool(metrics.get("trust_store_match")),
            "trust_scope": metrics.get("trust_scope"),
            "key_protection": metrics.get("key_protection"),
            "status": status,
            "last_error": agent_row.get("inspection_last_error"),
            "last_event_at": metrics.get("last_event_at") or self._format_timestamp(events_row.get("last_event_at")),
            "recent_event_count": int(events_row.get("recent_event_count") or 0),
            "last_upload_at": metrics.get("last_upload_at"),
            "proxy_port": metrics.get("proxy_port"),
            "proxy_pid": metrics.get("proxy_pid"),
            "queue_size": int(metrics.get("queue_size") or 0),
            "spooled_event_count": int(metrics.get("spooled_event_count") or 0),
            "dropped_event_count": int(metrics.get("dropped_event_count") or 0),
            "uploaded_event_count": int(metrics.get("uploaded_event_count") or 0),
            "upload_failures": int(metrics.get("upload_failures") or 0),
            "last_drop_reason": metrics.get("last_drop_reason"),
            "drop_reasons": metrics.get("drop_reasons") or {},
        }


web_inspection_service = WebInspectionService()
