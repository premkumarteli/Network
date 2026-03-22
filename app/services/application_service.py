from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional
import logging

from ..core.config import settings
from ..utils.asn_lookup import asn_lookup_service
from ..utils.domain_utils import get_base_domain, normalize_host
from ..utils.network import is_rfc1918_device_ip, normalize_ip
from .device_service import device_service

logger = logging.getLogger("netvisor.apps")

# Specific applications must be checked before generic umbrella providers.
APP_RULES: dict[str, list[str]] = {
    "YouTube": ["youtube.com", "googlevideo.com"],
    "Instagram": ["instagram.com"],
    "Facebook": ["facebook.com", "fbcdn.net", "messenger.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net"],
    "ChatGPT": ["openai.com", "chatgpt.com"],
    "GitHub": ["github.com", "githubassets.com", "githubusercontent.com"],
    "Perplexity": ["perplexity.ai", "perplexity.com"],
    "Microsoft": ["bing.com", "bingapis.com", "microsoft.com", "live.com", "gamepass.com", "xbox.com"],
    "Google": ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com"],
}

CONTROL_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
SHARED_INFRA_BASE_DOMAINS = {
    "amazonaws.com",
    "awsstatic.com",
    "cloudflare.com",
    "cloudfront.net",
    "akamaized.net",
    "akamaihd.net",
    "fastly.net",
}
UNCLASSIFIED_SENTINELS = {"", "Other", "Unknown", None}


class ApplicationService:
    def __init__(self) -> None:
        self._schema_ready = False
        self._unknown_debug_cache: set[tuple[str, str | None]] = set()

    def _row_value(self, row: Any, key: str) -> Any:
        if isinstance(row, dict):
            return row.get(key)
        return getattr(row, key, None)

    def _normalize_domain(self, value: object) -> Optional[str]:
        return normalize_host(value)

    def get_base_domain(self, domain: object) -> Optional[str]:
        return get_base_domain(domain)

    def _preferred_host(self, row: Any) -> Optional[str]:
        return self._normalize_domain(self._row_value(row, "sni") or self._row_value(row, "domain"))

    def classify_by_domain(self, domain: object) -> Optional[str]:
        """
        Classify using SNI/domain data.
        Returns:
        - concrete app name when matched
        - dynamically title-cased name of the domain if no specific rule matches
        - None when the host is missing/invalid or generic infrastructure should defer to ASN
        """
        normalized = self._normalize_domain(domain)
        if not normalized:
            return None

        base_domain = self.get_base_domain(normalized)
        if not base_domain:
            return None

        if base_domain in SHARED_INFRA_BASE_DOMAINS:
            return None

        for application, allowed_domains in APP_RULES.items():
            if base_domain in allowed_domains:
                return application
        
        # Instead of grouping everything unknown as "Other", use the base domain name.
        # Example: reddit.com -> Reddit
        name = base_domain.split('.')[0]
        if name:
            return name.title()
            
        return "Other"

    def classify_by_asn(self, ip_value: str | None) -> Optional[str]:
        return asn_lookup_service.classify_ip(ip_value)

    def classify_app(self, row: Any) -> str:
        """
        Classification priority:
        1. SNI
        2. DNS/host domain
        3. ASN fallback
        4. Unknown/Other separation
        """
        host = self._preferred_host(row)
        if host:
            domain_app = self.classify_by_domain(host)
            if domain_app and domain_app != "Other":
                return domain_app

        asn_app = self.classify_by_asn(self._row_value(row, "dst_ip"))
        if asn_app:
            return asn_app

        if host:
            return "Other"

        debug_key = (
            str(self._row_value(row, "dst_ip") or self._row_value(row, "src_ip") or ""),
            self._row_value(row, "network_scope"),
        )
        if debug_key not in self._unknown_debug_cache and len(self._unknown_debug_cache) < 512:
            self._unknown_debug_cache.add(debug_key)
            logger.debug(
                "Unknown traffic: src=%s dst=%s domain=%s sni=%s",
                self._row_value(row, "src_ip"),
                self._row_value(row, "dst_ip"),
                self._row_value(row, "domain"),
                self._row_value(row, "sni"),
            )
        return "Unknown"

    def _is_trackable_device_ip(self, value: str | None) -> bool:
        return is_rfc1918_device_ip(value)

    def _is_noise_flow(self, row: dict) -> bool:
        src_port = int(row.get("src_port") or 0)
        dst_port = int(row.get("dst_port") or 0)
        if src_port in CONTROL_PORTS or dst_port in CONTROL_PORTS:
            return True

        host = self._preferred_host(row)
        if not host:
            if row.get("network_scope") == "internal_lan":
                return True
            if not row.get("external_endpoint_ip"):
                return True
            return False

        return host.endswith(".in-addr.arpa") or host.endswith(".ip6.arpa") or host.endswith(".local")

    def _select_device_ip(self, row: dict) -> Optional[str]:
        internal_device_ip = normalize_ip(row.get("internal_device_ip"))
        if self._is_trackable_device_ip(internal_device_ip):
            return internal_device_ip

        src_ip = row.get("src_ip")
        dst_ip = row.get("dst_ip")
        src_trackable = self._is_trackable_device_ip(src_ip)
        dst_trackable = self._is_trackable_device_ip(dst_ip)

        if src_trackable and not dst_trackable:
            return src_ip
        if dst_trackable and not src_trackable:
            return dst_ip
        if src_trackable and dst_trackable:
            return src_ip
        return None

    def _session_domain_key(self, row: dict) -> str:
        host = self._preferred_host(row)
        if not host:
            return "-"
        return self.get_base_domain(host) or host

    def _fetch_recent_sessions(
        self,
        db_conn,
        organization_id: Optional[str],
        window_minutes: int,
    ) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [window_minutes]
            query = """
                SELECT
                    device_ip,
                    external_ip,
                    application,
                    domain,
                    protocol,
                    total_bytes,
                    total_packets,
                    first_seen,
                    last_seen
                FROM sessions
                WHERE last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += " ORDER BY last_seen DESC"
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
        finally:
            cursor.close()

    def _is_meaningful_session(self, row: dict) -> bool:
        device_ip = normalize_ip(row.get("device_ip"))
        if not self._is_trackable_device_ip(device_ip):
            return False

        host = self._preferred_host(row)
        external_ip = normalize_ip(row.get("external_ip"))
        protocol = str(row.get("protocol") or "").upper()

        if host and (host.endswith(".in-addr.arpa") or host.endswith(".ip6.arpa") or host.endswith(".local")):
            return False

        if not external_ip:
            if not host:
                return False
            if protocol == "UDP":
                return False
            if (row.get("application") or "Unknown") in {"Unknown", "Other"}:
                return False

        return True

    def _resolve_session_application(self, row: dict) -> str:
        stored_application = row.get("application")
        if stored_application not in UNCLASSIFIED_SENTINELS:
            return stored_application

        classified = self.classify_app(
            {
                "domain": row.get("domain"),
                "sni": None,
                "dst_ip": row.get("external_ip"),
            }
        )
        return classified

    def _build_sessions(self, db_conn, organization_id: Optional[str], window_minutes: int) -> list[dict]:
        rows = self._fetch_recent_sessions(db_conn, organization_id, window_minutes)
        sessions: list[dict] = []

        for row in rows:
            if not self._is_meaningful_session(row):
                continue

            host = self._preferred_host(row)
            sessions.append(
                {
                    "device_ip": normalize_ip(row.get("device_ip")),
                    "application": self._resolve_session_application(row),
                    "domain": self.get_base_domain(host) if host else "-",
                    "bandwidth_bytes": int(row.get("total_bytes") or 0),
                    "first_seen": row.get("first_seen") or row.get("last_seen"),
                    "last_seen": row.get("last_seen"),
                }
            )

        return sessions

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

    def _backfill_applications(self, db_conn, batch_size: int = 1000) -> None:
        """
        Safe backfill:
        - does not overwrite specifically classified rows
        - updates missing/legacy Other/Unknown rows using the new classifier
        """
        select_cursor = db_conn.cursor(dictionary=True)
        update_cursor = db_conn.cursor()
        try:
            last_id = 0
            while True:
                select_cursor.execute(
                    """
                    SELECT id, dst_ip, domain, sni, application
                    FROM flow_logs
                    WHERE id > %s
                      AND (application IS NULL OR application = '' OR application = 'Other' OR application = 'Unknown')
                    ORDER BY id
                    LIMIT %s
                    """,
                    (last_id, batch_size),
                )
                rows = select_cursor.fetchall()
                if not rows:
                    break

                updates = []
                for row in rows:
                    classified = self.classify_app(row)
                    if classified != (row.get("application") or ""):
                        updates.append((classified, row["id"]))

                if updates:
                    update_cursor.executemany(
                        "UPDATE flow_logs SET application = %s WHERE id = %s",
                        updates,
                    )
                    db_conn.commit()

                last_id = rows[-1]["id"]
        finally:
            select_cursor.close()
            update_cursor.close()

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return

        cursor = db_conn.cursor()
        try:
            if not self._column_exists(cursor, "flow_logs", "sni"):
                logger.info("Adding sni column to flow_logs.")
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN sni VARCHAR(255) NULL AFTER domain
                    """
                )

            if not self._column_exists(cursor, "flow_logs", "application"):
                logger.info("Adding application column to flow_logs.")
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN application VARCHAR(50) NOT NULL DEFAULT 'Other' AFTER sni
                    """
                )

            if not self._index_exists(cursor, "flow_logs", "idx_flow_logs_org_app_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_flow_logs_org_app_last_seen
                    ON flow_logs (organization_id, application, last_seen)
                    """
                )

            if not self._index_exists(cursor, "flow_logs", "idx_flow_logs_app_src_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_flow_logs_app_src_last_seen
                    ON flow_logs (application, src_ip, last_seen)
                    """
                )

            if not self._index_exists(cursor, "flow_logs", "idx_flow_logs_sni_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_flow_logs_sni_last_seen
                    ON flow_logs (sni, last_seen)
                    """
                )

            db_conn.commit()
            self._schema_ready = True
        finally:
            cursor.close()

    def _format_bytes(self, byte_count: float) -> str:
        if byte_count >= 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        if byte_count >= 1024:
            return f"{byte_count / 1024:.1f} KB"
        return f"{int(byte_count)} B"

    def _format_timestamp(self, value) -> str:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value or "")

    def _runtime_seconds(self, first_seen, last_seen) -> int:
        if not last_seen and not first_seen:
            return 0
        if not first_seen:
            return 0
        if not last_seen:
            return 0
        try:
            delta = last_seen - first_seen
            return max(int(delta.total_seconds()), 0)
        except Exception:
            return 0

    def _format_runtime(self, seconds: int) -> str:
        seconds = max(int(seconds or 0), 0)
        hours, remainder = divmod(seconds, 3600)
        minutes, remaining_seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m"
        if minutes:
            return f"{minutes}m {remaining_seconds}s"
        return f"{remaining_seconds}s"

    def get_application_summary(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        window_minutes: int = 5,
        active_window_seconds: int = 60,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        active_cutoff = datetime.utcnow() - timedelta(seconds=active_window_seconds)
        grouped: dict[str, dict] = {}
        for session in self._build_sessions(db_conn, organization_id, window_minutes):
            application = session["application"]
            entry = grouped.get(application)
            is_active = bool(session.get("last_seen") and session["last_seen"] >= active_cutoff)
            if entry is None:
                grouped[application] = {
                    "application": application,
                    "device_ips": {session["device_ip"]},
                    "active_device_ips": {session["device_ip"]} if is_active else set(),
                    "bandwidth_bytes": session["bandwidth_bytes"],
                    "runtime_seconds": self._runtime_seconds(
                        session.get("first_seen"), session.get("last_seen")
                    ),
                    "last_seen": session["last_seen"],
                }
            else:
                entry["device_ips"].add(session["device_ip"])
                if is_active:
                    entry["active_device_ips"].add(session["device_ip"])
                entry["bandwidth_bytes"] += session["bandwidth_bytes"]
                entry["runtime_seconds"] += self._runtime_seconds(
                    session.get("first_seen"), session.get("last_seen")
                )
                if session["last_seen"] and session["last_seen"] > entry["last_seen"]:
                    entry["last_seen"] = session["last_seen"]

        results = []
        for entry in grouped.values():
            results.append(
                {
                    "application": entry["application"],
                    "device_count": len(entry["device_ips"]),
                    "active_device_count": len(entry["active_device_ips"]),
                    "bandwidth_bytes": int(entry["bandwidth_bytes"] or 0),
                    "bandwidth": self._format_bytes(float(entry["bandwidth_bytes"] or 0)),
                    "runtime_seconds": int(entry["runtime_seconds"] or 0),
                    "runtime": self._format_runtime(int(entry["runtime_seconds"] or 0)),
                    "last_seen": self._format_timestamp(entry["last_seen"]),
                }
            )

        results.sort(
            key=lambda item: (
                -item["active_device_count"],
                -item["device_count"],
                -item["bandwidth_bytes"],
                item["application"],
            )
        )
        return results

    def get_application_devices(
        self,
        db_conn,
        app_name: str,
        organization_id: Optional[str] = None,
        window_minutes: int = 5,
        active_window_seconds: int = 60,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        active_cutoff = datetime.utcnow() - timedelta(seconds=active_window_seconds)
        device_lookup = {
            device.get("ip"): device
            for device in device_service.get_devices(db_conn, organization_id=organization_id)
        }
        sessions = [
            session
            for session in self._build_sessions(db_conn, organization_id, window_minutes)
            if session["application"] == app_name
        ]

        results = []
        for session in sessions:
            device = device_lookup.get(session["device_ip"], {})
            is_active = bool(session.get("last_seen") and session["last_seen"] >= active_cutoff)
            results.append(
                {
                    "device_ip": session["device_ip"],
                    "hostname": device.get("hostname") or "Unknown",
                    "status": "Active" if is_active else "Idle",
                    "bandwidth_bytes": int(session["bandwidth_bytes"] or 0),
                    "bandwidth": self._format_bytes(float(session["bandwidth_bytes"] or 0)),
                    "runtime_seconds": self._runtime_seconds(
                        session.get("first_seen"), session.get("last_seen")
                    ),
                    "runtime": self._format_runtime(
                        self._runtime_seconds(session.get("first_seen"), session.get("last_seen"))
                    ),
                    "last_seen": self._format_timestamp(session["last_seen"]),
                    "management_mode": device.get("management_mode") or "byod",
                }
            )

        results.sort(
            key=lambda item: (
                0 if item["status"] == "Active" else 1,
                -item["bandwidth_bytes"],
                item["device_ip"],
            )
        )
        return results

    def get_top_other_domains(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        limit: int = 20,
    ) -> list[dict]:
        """
        Optional analytics helper for investigating uncategorized but known domains.
        """
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            query = """
                SELECT
                    COALESCE(NULLIF(sni, ''), NULLIF(domain, '')) AS host,
                    COUNT(*) AS flow_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes,
                    MAX(last_seen) AS last_seen
                FROM flow_logs
                WHERE application = 'Other'
                  AND COALESCE(NULLIF(sni, ''), NULLIF(domain, '')) IS NOT NULL
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY host
                ORDER BY flow_count DESC, bandwidth_bytes DESC
                LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = []
            for row in cursor.fetchall():
                rows.append(
                    {
                        "host": row.get("host"),
                        "base_domain": self.get_base_domain(row.get("host")) or row.get("host"),
                        "flow_count": int(row.get("flow_count") or 0),
                        "bandwidth_bytes": int(row.get("bandwidth_bytes") or 0),
                        "last_seen": self._format_timestamp(row.get("last_seen")),
                    }
                )
            return rows
        finally:
            cursor.close()


application_service = ApplicationService()
