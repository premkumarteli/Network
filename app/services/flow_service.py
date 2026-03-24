import asyncio
import json
import logging
from datetime import datetime, timezone

from ..core.config import settings
from ..db.session import get_db_connection
from ..realtime import emit_event
from .application_service import application_service
from .device_service import device_service
from .external_endpoint_service import external_endpoint_service
from .flow_sanitization_service import flow_sanitization_service
from .managed_device_service import managed_device_service
from .risk_engine import risk_engine
from .session_service import session_service
from .system_service import system_service

logger = logging.getLogger("netvisor.services.flow")

# Buffered queues for high-performance ingestion
flow_queue = asyncio.Queue(maxsize=10000)

class FlowService:
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

    def _ensure_runtime_tables(self, db_conn) -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS device_baselines (
                    device_id VARCHAR(100) PRIMARY KEY,
                    organization_id CHAR(36),
                    ip_address VARCHAR(50),
                    avg_connections_per_min FLOAT DEFAULT 0,
                    avg_unique_destinations FLOAT DEFAULT 0,
                    avg_flow_duration FLOAT DEFAULT 0,
                    std_dev_connections FLOAT DEFAULT 0,
                    last_computed DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            db_conn.commit()
        finally:
            cursor.close()

    def _ensure_flow_log_schema(self, db_conn) -> None:
        cursor = db_conn.cursor()
        try:
            if not self._column_exists(cursor, "flow_logs", "src_mac"):
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN src_mac VARCHAR(20) NULL AFTER sni
                    """
                )

            if not self._column_exists(cursor, "flow_logs", "dst_mac"):
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN dst_mac VARCHAR(20) NULL AFTER src_mac
                    """
                )

            if not self._column_exists(cursor, "flow_logs", "network_scope"):
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN network_scope VARCHAR(20) NOT NULL DEFAULT 'unknown' AFTER dst_mac
                    """
                )

            if not self._column_exists(cursor, "flow_logs", "internal_device_ip"):
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN internal_device_ip VARCHAR(50) NULL AFTER network_scope
                    """
                )

            if not self._column_exists(cursor, "flow_logs", "external_endpoint_ip"):
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN external_endpoint_ip VARCHAR(50) NULL AFTER internal_device_ip
                    """
                )

            if not self._column_exists(cursor, "flow_logs", "session_id"):
                cursor.execute(
                    """
                    ALTER TABLE flow_logs
                    ADD COLUMN session_id CHAR(40) NULL AFTER external_endpoint_ip
                    """
                )

            if not self._index_exists(cursor, "flow_logs", "idx_flow_logs_internal_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_flow_logs_internal_last_seen
                    ON flow_logs (internal_device_ip, last_seen)
                    """
                )

            if not self._index_exists(cursor, "flow_logs", "idx_flow_logs_scope_last_seen"):
                cursor.execute(
                    """
                    CREATE INDEX idx_flow_logs_scope_last_seen
                    ON flow_logs (network_scope, last_seen)
                    """
                )

            if not self._index_exists(cursor, "flow_logs", "idx_flow_logs_session_id"):
                cursor.execute(
                    """
                    CREATE INDEX idx_flow_logs_session_id
                    ON flow_logs (session_id)
                    """
                )

            db_conn.commit()
        finally:
            cursor.close()

    def classify_management_mode(self, flow_data, managed_ip_set: set[str]) -> str:
        source_type = getattr(flow_data, "source_type", "agent")
        if source_type == "agent":
            return "managed"
        internal_ip = getattr(flow_data, "internal_device_ip", None) or getattr(flow_data, "src_ip", "")
        return "managed" if internal_ip in managed_ip_set else "byod"

    def build_alert_breakdown(self, report: dict, management_mode: str, source_type: str, metadata_only: bool) -> dict:
        breakdown = dict(report.get("breakdown", {}))
        breakdown.update(
            {
                "management_mode": management_mode,
                "source_type": source_type,
                "metadata_only": metadata_only,
                "application": report.get("application", "Other"),
                "reasons": report.get("reasons", []),
                "signals": report.get("signals", []),
                "primary_detection": report.get("primary_detection"),
            }
        )
        return breakdown

    def _mysql_timestamp(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is not None:
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return value

    def _resolve_organization_id(self, cursor, requested_org_id: str | None, cache: dict[str | None, str | None]) -> str | None:
        if requested_org_id in cache:
            return cache[requested_org_id]

        resolved_org_id = requested_org_id

        if requested_org_id and not settings.SINGLE_ORG_MODE:
            cursor.execute("SELECT id FROM organizations WHERE id = %s LIMIT 1", (requested_org_id,))
            org_row = cursor.fetchone()
            resolved_org_id = org_row["id"] if org_row else None
        else:
            cursor.execute("SELECT id FROM organizations LIMIT 1")
            org_row = cursor.fetchone()
            resolved_org_id = org_row["id"] if org_row else (requested_org_id or settings.DEFAULT_ORGANIZATION_ID)

        if resolved_org_id != requested_org_id:
            logger.debug(
                "Normalized flow organization_id from %r to %r",
                requested_org_id,
                resolved_org_id,
            )

        cache[requested_org_id] = resolved_org_id
        return resolved_org_id

    def _record_device_activity(
        self,
        observations: dict[tuple[str | None, str], dict],
        *,
        ip: str | None,
        organization_id: str | None,
        seen_at,
        agent_id: str | None = None,
    ) -> None:
        if not device_service._is_trackable_device_ip(ip):
            return

        normalized_seen_at = device_service._parse_timestamp(seen_at) or seen_at
        key = (organization_id, ip)
        existing = observations.get(key)
        if existing is None:
            observations[key] = {
                "ip": ip,
                "organization_id": organization_id,
                "seen_at": normalized_seen_at,
                "agent_id": agent_id,
            }
        elif (
            normalized_seen_at
            and (
                existing.get("seen_at") is None
                or normalized_seen_at > existing["seen_at"]
            )
        ):
            observations[key] = {
                "ip": ip,
                "organization_id": organization_id,
                "seen_at": normalized_seen_at,
                "agent_id": agent_id or existing.get("agent_id"),
            }
        elif agent_id and not existing.get("agent_id"):
            existing["agent_id"] = agent_id

    async def buffer_flow(self, flow_data):
        try:
            flow_queue.put_nowait(flow_data)
            return True
        except asyncio.QueueFull:
            logger.error("Flow queue full - dropping flow")
            return False

    async def flow_writer_worker(self):
        """Async worker to persist flows and trigger detection."""
        while True:
            batch = []
            # Get first item
            item = await flow_queue.get()
            batch.append(item)
            
            # Try to get more for a batch
            while len(batch) < 100:
                try:
                    item = flow_queue.get_nowait()
                    batch.append(item)
                except asyncio.QueueEmpty:
                    break
            
            if batch:
                # Offload DB-heavy work to a thread to avoid blocking the event loop
                events_to_emit = await asyncio.to_thread(self._sync_persist_batch, batch)
                
                # Emit events in the main event loop
                for event_name, payload in events_to_emit:
                    await emit_event(event_name, payload)

                for _ in range(len(batch)):
                    flow_queue.task_done()

    async def _persist_batch(self, batch):
        """No longer used directly, superseded by _sync_persist_batch + to_thread."""
        events_to_emit = await asyncio.to_thread(self._sync_persist_batch, batch)
        for event_name, payload in events_to_emit:
            await emit_event(event_name, payload)

    def _sync_persist_batch(self, batch) -> list[tuple[str, dict]]:
        """Synchronous version of persist_batch to be run in a thread."""
        events_to_emit = []
        conn = get_db_connection()
        if not conn: return []
        cursor = None
        try:
            if not self._schema_ready:
                managed_device_service.ensure_table(conn)
                self._ensure_runtime_tables(conn)
                self._ensure_flow_log_schema(conn)
                application_service.ensure_schema(conn)
                system_service.ensure_tables(conn)
                external_endpoint_service.ensure_table(conn)
                session_service.ensure_table(conn)
                self._schema_ready = True
            
            if not system_service.is_monitoring_enabled(conn):
                # Using print for logging in a separate thread if logger is not thread-safe, 
                # but standard python logging is generally thread-safe.
                logger.debug(f"Monitoring disabled, dropping {len(batch)} buffered flow(s)")
                return []

            cursor = conn.cursor(dictionary=True)
            managed_ip_cache = {}
            organization_cache = {}
            seen_hashes: set[str] = set()

            for flow in batch:
                org_id = self._resolve_organization_id(
                    cursor,
                    getattr(flow, "organization_id", None),
                    organization_cache,
                )
                sanitized = flow_sanitization_service.sanitize_flow(flow, organization_id=org_id)
                if not sanitized:
                    continue
                if sanitized.ingest_hash in seen_hashes:
                    continue
                seen_hashes.add(sanitized.ingest_hash)

                if org_id not in managed_ip_cache:
                    managed_ip_cache[org_id] = managed_device_service.get_managed_ip_set(conn, org_id)

                management_mode = self.classify_management_mode(sanitized, managed_ip_cache[org_id])
                source_type = sanitized.source_type
                metadata_only = sanitized.metadata_only

                baseline = None
                if sanitized.internal_device_ip:
                    cursor.execute(
                        "SELECT * FROM device_baselines WHERE device_id = %s",
                        (sanitized.internal_device_ip,),
                    )
                    baseline = cursor.fetchone()
                 
                report = risk_engine.evaluate_flow(sanitized, baseline)
                application = application_service.classify_app(sanitized)
                report["application"] = application
                breakdown = self.build_alert_breakdown(report, management_mode, source_type, metadata_only)
                breakdown.update(
                    {
                        "network_scope": sanitized.network_scope,
                        "internal_device_ip": sanitized.internal_device_ip,
                        "external_endpoint_ip": sanitized.external_endpoint_ip,
                    }
                )

                session_id = None
                if sanitized.internal_device_ip:
                    session_id = session_service.upsert_session(
                        conn,
                        organization_id=org_id,
                        device_ip=sanitized.internal_device_ip,
                        device_mac=sanitized.internal_device_mac,
                        external_ip=sanitized.external_endpoint_ip,
                        application=application,
                        domain=sanitized.sni or sanitized.domain,
                        protocol=sanitized.protocol,
                        source_type=source_type,
                        packet_count=sanitized.packet_count,
                        byte_count=sanitized.byte_count,
                        start_time=self._mysql_timestamp(sanitized.start_time),
                        last_seen=self._mysql_timestamp(sanitized.last_seen),
                        duration=sanitized.duration,
                    )

                external_endpoint_service.observe_endpoint(
                    conn,
                    endpoint_ip=sanitized.external_endpoint_ip,
                    organization_id=org_id,
                    domain=sanitized.sni or sanitized.domain,
                    application=application,
                    byte_count=sanitized.byte_count,
                )
                 
                sql = """
                    INSERT INTO flow_logs (
                        organization_id, src_ip, dst_ip, src_port, dst_port,
                        protocol, start_time, last_seen, packet_count, byte_count,
                        duration, average_packet_size, domain, sni, src_mac, dst_mac,
                        network_scope, internal_device_ip, external_endpoint_ip, session_id,
                        application, agent_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    org_id,
                    sanitized.src_ip,
                    sanitized.dst_ip,
                    sanitized.src_port,
                    sanitized.dst_port,
                    sanitized.protocol,
                    self._mysql_timestamp(sanitized.start_time),
                    self._mysql_timestamp(sanitized.last_seen),
                    sanitized.packet_count,
                    sanitized.byte_count,
                    sanitized.duration,
                    sanitized.average_packet_size,
                    sanitized.domain,
                    sanitized.sni,
                    sanitized.src_mac,
                    sanitized.dst_mac,
                    sanitized.network_scope,
                    sanitized.internal_device_ip,
                    sanitized.external_endpoint_ip,
                    session_id,
                    application,
                    sanitized.agent_id,
                ))

                if sanitized.internal_device_ip:
                    device_service.touch_device_seen(
                        conn,
                        ip=sanitized.internal_device_ip,
                        organization_id=org_id,
                        seen_at=sanitized.last_seen,
                        agent_id=sanitized.agent_id if management_mode == "managed" else None,
                        mac=sanitized.internal_device_mac,
                        create_if_missing=(source_type == "agent" and bool(sanitized.internal_device_mac)),
                    )

                    cursor.execute("""
                        INSERT INTO device_risks (device_id, current_score, risk_level, reasons)
                        VALUES (%s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE 
                            current_score = VALUES(current_score),
                            risk_level = VALUES(risk_level),
                            reasons = VALUES(reasons)
                    """, (
                        sanitized.internal_device_ip,
                        report["score"],
                        report["severity"],
                        ",".join(report["reasons"]),
                    ))

                if sanitized.internal_device_ip and report["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                    cursor.execute("""
                        INSERT INTO alerts (organization_id, device_ip, severity, risk_score, breakdown_json)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        org_id,
                        sanitized.internal_device_ip,
                        report["severity"],
                        report["score"],
                        json.dumps(breakdown),
                    ))

                events_to_emit.append((
                    "packet_event",
                    {
                        "time_str": str(self._mysql_timestamp(sanitized.last_seen) or ""),
                        "src_ip": sanitized.src_ip,
                        "dst_ip": sanitized.dst_ip,
                        "domain": sanitized.sni or sanitized.domain or "-",
                        "application": application,
                        "protocol": sanitized.protocol,
                        "size": sanitized.byte_count,
                        "severity": report["severity"],
                        "risk_score": report["score"],
                        "management_mode": management_mode,
                        "network_scope": sanitized.network_scope,
                    },
                ))

            conn.commit()
            return events_to_emit
        except Exception as e:
            logger.error(f"Flow Persistence Error: {e}")
            if conn:
                conn.rollback()
            return []
        finally:
            if cursor:
                cursor.close()
            conn.close()

flow_service = FlowService()
