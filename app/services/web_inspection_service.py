from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..core.config import settings
from ..utils.domain_utils import get_base_domain, normalize_host

logger = logging.getLogger("netvisor.web_inspection")


class WebInspectionService:
    DEFAULT_ALLOWED_PROCESSES = ["chrome.exe", "msedge.exe"]
    DEFAULT_ALLOWED_DOMAINS = [
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
            base_domain = get_base_domain(host) or host
            if base_domain not in normalized:
                normalized.append(base_domain)
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

    def _default_policy(self, agent_id: Optional[str], device_ip: str) -> dict:
        return {
            "agent_id": agent_id,
            "device_ip": device_ip,
            "inspection_enabled": False,
            "allowed_processes": list(self.DEFAULT_ALLOWED_PROCESSES),
            "allowed_domains": list(self.DEFAULT_ALLOWED_DOMAINS),
            "snippet_max_bytes": self.DEFAULT_SNIPPET_MAX_BYTES,
            "updated_at": None,
        }

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS inspection_policies (
                    agent_id VARCHAR(100) NOT NULL,
                    device_ip VARCHAR(50) NOT NULL,
                    organization_id CHAR(36) NULL,
                    inspection_enabled BOOLEAN DEFAULT FALSE,
                    allowed_processes_json TEXT,
                    allowed_domains_json TEXT,
                    snippet_max_bytes INT DEFAULT 256,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (agent_id, device_ip),
                    INDEX idx_inspection_policies_device (device_ip),
                    INDEX idx_inspection_policies_org (organization_id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS web_events (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36) NULL,
                    agent_id VARCHAR(100) NOT NULL,
                    device_ip VARCHAR(50) NOT NULL,
                    process_name VARCHAR(100) NOT NULL,
                    browser_name VARCHAR(100) NOT NULL,
                    page_url TEXT NOT NULL,
                    base_domain VARCHAR(255) NOT NULL,
                    page_title VARCHAR(255) DEFAULT 'Untitled',
                    content_category VARCHAR(100) DEFAULT 'web',
                    content_id VARCHAR(255) NULL,
                    http_method VARCHAR(16) DEFAULT 'GET',
                    status_code INT NULL,
                    content_type VARCHAR(120) NULL,
                    request_bytes INT DEFAULT 0,
                    response_bytes INT DEFAULT 0,
                    snippet_redacted TEXT NULL,
                    snippet_hash VARCHAR(64) NULL,
                    first_seen DATETIME NULL,
                    last_seen DATETIME NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_web_events_device_last_seen (device_ip, last_seen),
                    INDEX idx_web_events_agent_last_seen (agent_id, last_seen),
                    INDEX idx_web_events_org_last_seen (organization_id, last_seen),
                    INDEX idx_web_events_base_domain_last_seen (base_domain, last_seen)
                )
                """
            )
            db_conn.commit()
            self._schema_ready = True
        finally:
            cursor.close()

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
            "allowed_domains": self._normalize_domains(
                self._json_loads(row.get("allowed_domains_json"), list(self.DEFAULT_ALLOWED_DOMAINS))
            ),
            "snippet_max_bytes": min(
                max(int(row.get("snippet_max_bytes") or self.DEFAULT_SNIPPET_MAX_BYTES), 0),
                self.DEFAULT_SNIPPET_MAX_BYTES,
            ),
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
            "allowed_domains": self._normalize_domains(
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

    def _coerce_event(self, event: dict) -> Optional[tuple]:
        device_ip = str(event.get("device_ip") or "").strip()
        agent_id = str(event.get("agent_id") or "").strip()
        if not device_ip or not agent_id:
            return None

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
            str(event.get("base_domain") or ""),
            str(event.get("page_title") or "Untitled")[:255],
            str(event.get("content_category") or "web")[:100],
            str(event.get("content_id") or "")[:255] or None,
            str(event.get("http_method") or "GET")[:16],
            int(event.get("status_code")) if event.get("status_code") not in (None, "") else None,
            str(event.get("content_type") or "")[:120] or None,
            max(int(event.get("request_bytes") or 0), 0),
            max(int(event.get("response_bytes") or 0), 0),
            event.get("snippet_redacted"),
            str(event.get("snippet_hash") or "")[:64] or None,
            first_seen.astimezone(timezone.utc).replace(tzinfo=None),
            last_seen.astimezone(timezone.utc).replace(tzinfo=None),
        )

    def store_events(self, db_conn, events: list[dict]) -> int:
        self.ensure_schema(db_conn)
        if not events:
            return 0

        self.purge_expired_events(db_conn)
        rows = [row for row in (self._coerce_event(event) for event in events) if row]
        if not rows:
            return 0

        cursor = db_conn.cursor()
        try:
            cursor.executemany(
                """
                INSERT INTO web_events (
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
                    http_method,
                    status_code,
                    content_type,
                    request_bytes,
                    response_bytes,
                    snippet_redacted,
                    snippet_hash,
                    first_seen,
                    last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
            db_conn.commit()
            return len(rows)
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
        self.ensure_schema(db_conn)
        self.purge_expired_events(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT
                    page_url,
                    base_domain,
                    page_title,
                    browser_name,
                    process_name,
                    content_category,
                    content_id,
                    http_method,
                    status_code,
                    content_type,
                    request_bytes,
                    response_bytes,
                    snippet_redacted,
                    first_seen,
                    last_seen
                FROM web_events
                WHERE device_ip = %s
                  AND (%s IS NULL OR organization_id = %s OR organization_id IS NULL)
                ORDER BY last_seen DESC, id DESC
                LIMIT %s
                """,
                (device_ip, organization_id, organization_id, limit),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()

        return [
            {
                "page_url": row.get("page_url"),
                "base_domain": row.get("base_domain"),
                "page_title": row.get("page_title") or "Untitled",
                "browser_name": row.get("browser_name") or "Unknown",
                "process_name": row.get("process_name") or "unknown",
                "content_category": row.get("content_category") or "web",
                "content_id": row.get("content_id"),
                "http_method": row.get("http_method") or "GET",
                "status_code": row.get("status_code"),
                "content_type": row.get("content_type"),
                "request_bytes": int(row.get("request_bytes") or 0),
                "response_bytes": int(row.get("response_bytes") or 0),
                "snippet_redacted": row.get("snippet_redacted"),
                "first_seen": self._format_timestamp(row.get("first_seen")),
                "last_seen": self._format_timestamp(row.get("last_seen")),
            }
            for row in rows
        ]

    def get_global_activity(
        self,
        db_conn,
        *,
        organization_id: Optional[str],
        limit: int = 50,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        self.purge_expired_events(db_conn)

        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT
                    agent_id,
                    device_ip,
                    page_url,
                    base_domain,
                    page_title,
                    browser_name,
                    process_name,
                    content_category,
                    content_id,
                    http_method,
                    status_code,
                    content_type,
                    request_bytes,
                    response_bytes,
                    snippet_redacted,
                    first_seen,
                    last_seen
                FROM web_events
                WHERE (%s IS NULL OR organization_id = %s OR organization_id IS NULL)
                ORDER BY last_seen DESC, id DESC
                LIMIT %s
                """,
                (organization_id, organization_id, limit),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()

        return [
            {
                "agent_id": row.get("agent_id"),
                "device_ip": row.get("device_ip"),
                "page_url": row.get("page_url"),
                "base_domain": row.get("base_domain"),
                "page_title": row.get("page_title") or "Untitled",
                "browser_name": row.get("browser_name") or "Unknown",
                "process_name": row.get("process_name") or "unknown",
                "content_category": row.get("content_category") or "web",
                "content_id": row.get("content_id"),
                "http_method": row.get("http_method") or "GET",
                "status_code": row.get("status_code"),
                "content_type": row.get("content_type"),
                "request_bytes": int(row.get("request_bytes") or 0),
                "response_bytes": int(row.get("response_bytes") or 0),
                "snippet_redacted": row.get("snippet_redacted"),
                "first_seen": self._format_timestamp(row.get("first_seen")),
                "last_seen": self._format_timestamp(row.get("last_seen")),
            }
            for row in rows
        ]

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
                    inspection_last_error
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
        status = agent_row.get("inspection_status") or ("enabled" if policy["inspection_enabled"] else "disabled")

        return {
            "agent_id": agent_id,
            "device_ip": device_ip,
            "inspection_enabled": bool(policy["inspection_enabled"]),
            "allowed_processes": list(policy["allowed_processes"]),
            "allowed_domains": list(policy["allowed_domains"]),
            "snippet_max_bytes": int(policy["snippet_max_bytes"]),
            "updated_at": policy.get("updated_at"),
            "browser_support": browsers,
            "proxy_running": bool(agent_row.get("inspection_proxy_running")),
            "ca_installed": bool(agent_row.get("inspection_ca_installed")),
            "status": status,
            "last_error": agent_row.get("inspection_last_error"),
            "last_event_at": self._format_timestamp(events_row.get("last_event_at")),
            "recent_event_count": int(events_row.get("recent_event_count") or 0),
        }


web_inspection_service = WebInspectionService()
