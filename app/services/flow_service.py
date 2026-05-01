import asyncio
from hashlib import sha256
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import mysql.connector
from pydantic import TypeAdapter

from ..core.config import settings
from ..db.session import require_runtime_schema
from ..db.session import get_db_connection
from ..realtime import emit_event
from ..schemas.flow_schema import FlowBase
from .application_service import application_service
from .device_service import device_service
from .external_endpoint_service import external_endpoint_service
from .flow_sanitization_service import flow_sanitization_service
from .managed_device_service import managed_device_service
from .metrics_service import metrics_service
from .risk_engine import risk_engine
from .session_service import session_service
from .system_service import system_service

logger = logging.getLogger("netvisor.services.flow")


FLOW_WORKER_TYPE = "flow_ingest"
FLOW_BATCH_ADAPTER = TypeAdapter(list[FlowBase])


class FlowQueueBackpressureError(RuntimeError):
    """Raised when the durable flow queue is too far behind to accept more work."""


class FlowService:
    def __init__(self) -> None:
        self._schema_ready = False
        self._metrics_lock = threading.Lock()
        self._worker_id = f"flow-worker-{uuid.uuid4().hex[:12]}"
        self._metrics = {
            "queue_depth": 0,
            "pending_batches": 0,
            "pending_flows": 0,
            "processing_batches": 0,
            "processing_flows": 0,
            "processed_batches": 0,
            "deadletter_batches": 0,
            "oldest_pending_age_seconds": 0,
            "active_workers": 0,
            "worker_alive": False,
            "buffered_batches_total": 0,
            "buffered_flows_total": 0,
            "dropped_flows_total": 0,
            "deduplicated_batches_total": 0,
            "deduplicated_flows_total": 0,
            "backpressure_rejections_total": 0,
            "processed_batches_total": 0,
            "processed_flows_total": 0,
            "failed_batches_total": 0,
            "requeued_batches_total": 0,
            "deadletter_batches_total": 0,
            "emitted_events_total": 0,
            "last_batch_size": 0,
            "last_persist_duration_ms": 0.0,
            "last_emit_duration_ms": 0.0,
            "last_claimed_batch_id": None,
            "last_error": None,
            "last_processed_at": None,
            "worker_mode": None,
        }
        self._queue_status_cache: dict | None = None
        self._queue_status_cache_ts = 0.0

    def _set_metric(self, key: str, value) -> None:
        with self._metrics_lock:
            self._metrics[key] = value

    def _increment_metric(self, key: str, amount: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[key] = int(self._metrics.get(key) or 0) + amount

    def _queue_status_counts(self, db_conn=None, *, force: bool = False) -> dict | None:
        cache_ttl = max(float(settings.FLOW_QUEUE_STATUS_CACHE_SECONDS or 1.0), 0.0)
        now = time.monotonic()
        if not force:
            with self._metrics_lock:
                if self._queue_status_cache is not None and (now - self._queue_status_cache_ts) < cache_ttl:
                    return dict(self._queue_status_cache)

        owned_conn = db_conn is None
        conn = db_conn or get_db_connection()
        cursor = None
        try:
            require_runtime_schema(conn)
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT status, COUNT(*) AS batch_count, COALESCE(SUM(flow_count), 0) AS flow_count
                FROM flow_ingest_batches
                GROUP BY status
                """
            )
            counts = {
                "pending_batches": 0,
                "pending_flows": 0,
                "processing_batches": 0,
                "processing_flows": 0,
                "processed_batches": 0,
                "deadletter_batches": 0,
                "oldest_pending_age_seconds": 0,
                "active_workers": 0,
            }
            for row in cursor.fetchall() or []:
                status = str(row.get("status") or "").strip().lower()
                batch_count = int(row.get("batch_count") or 0)
                flow_count = int(row.get("flow_count") or 0)
                if status == "pending":
                    counts["pending_batches"] = batch_count
                    counts["pending_flows"] = flow_count
                elif status == "processing":
                    counts["processing_batches"] = batch_count
                    counts["processing_flows"] = flow_count
                elif status == "processed":
                    counts["processed_batches"] = batch_count
                elif status == "deadletter":
                    counts["deadletter_batches"] = batch_count

            cursor.execute(
                """
                SELECT COALESCE(TIMESTAMPDIFF(SECOND, MIN(available_at), UTC_TIMESTAMP()), 0) AS age_seconds
                FROM flow_ingest_batches
                WHERE status = 'pending'
                  AND available_at <= UTC_TIMESTAMP()
                """
            )
            age_row = cursor.fetchone() or {}
            counts["oldest_pending_age_seconds"] = max(int(age_row.get("age_seconds") or 0), 0)

            cursor.execute(
                """
                SELECT COUNT(*) AS worker_count
                FROM worker_heartbeats
                WHERE worker_type = %s
                  AND last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s SECOND)
                """,
                (
                    FLOW_WORKER_TYPE,
                    max(int(settings.FLOW_WORKER_ALIVE_SECONDS or 15), 1),
                ),
            )
            heartbeat_row = cursor.fetchone() or {}
            counts["active_workers"] = max(int(heartbeat_row.get("worker_count") or 0), 0)
            with self._metrics_lock:
                self._queue_status_cache = dict(counts)
                self._queue_status_cache_ts = now
            return counts
        except Exception:
            return None
        finally:
            if cursor:
                cursor.close()
            if owned_conn and conn:
                conn.close()

    def _refresh_queue_depth(self, db_conn=None) -> None:
        counts = self._queue_status_counts(db_conn)
        if counts is None:
            return

        self._set_metric("queue_depth", counts["pending_flows"])
        self._set_metric("pending_batches", counts["pending_batches"])
        self._set_metric("pending_flows", counts["pending_flows"])
        self._set_metric("processing_batches", counts["processing_batches"])
        self._set_metric("processing_flows", counts["processing_flows"])
        self._set_metric("processed_batches", counts["processed_batches"])
        self._set_metric("deadletter_batches", counts["deadletter_batches"])
        self._set_metric("oldest_pending_age_seconds", counts["oldest_pending_age_seconds"])
        self._set_metric("active_workers", counts["active_workers"])
        self._set_metric("worker_alive", counts["active_workers"] > 0)
        metrics_service.set_gauge("flow_queue_depth", counts["pending_flows"])
        metrics_service.set_gauge("flow_pending_batches", counts["pending_batches"])
        metrics_service.set_gauge("flow_processing_flows", counts["processing_flows"])
        metrics_service.set_gauge("flow_processing_batches", counts["processing_batches"])
        metrics_service.set_gauge("flow_deadletter_batches", counts["deadletter_batches"])
        metrics_service.set_gauge("flow_oldest_pending_age_seconds", counts["oldest_pending_age_seconds"])
        metrics_service.set_gauge("flow_active_workers", counts["active_workers"])

    def metrics_snapshot(self) -> dict:
        self._refresh_queue_depth()
        with self._metrics_lock:
            snapshot = dict(self._metrics)
        return snapshot

    def _payload_json(self, payloads: list[dict]) -> str:
        return json.dumps(payloads, sort_keys=True, separators=(",", ":"))

    def _batch_id_from_payload_json(self, payload_json: str) -> str:
        return sha256(payload_json.encode("utf-8")).hexdigest()

    def _enforce_backpressure(self, db_conn, incoming_flows: int) -> None:
        counts = self._queue_status_counts(db_conn) or {}
        pending_flows = max(int(counts.get("pending_flows") or 0), 0)
        oldest_pending_age = max(int(counts.get("oldest_pending_age_seconds") or 0), 0)

        max_pending_flows = max(int(settings.FLOW_INGEST_MAX_PENDING_FLOWS or 0), 0)
        if max_pending_flows and (pending_flows + max(int(incoming_flows or 0), 0)) > max_pending_flows:
            raise FlowQueueBackpressureError(
                f"Flow ingest queue depth {pending_flows} exceeds configured limit {max_pending_flows}."
            )

        max_lag_seconds = max(int(settings.FLOW_INGEST_MAX_LAG_SECONDS or 0), 0)
        if max_lag_seconds and oldest_pending_age > max_lag_seconds:
            raise FlowQueueBackpressureError(
                f"Flow ingest lag {oldest_pending_age}s exceeds configured limit {max_lag_seconds}s."
            )

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
        require_runtime_schema(db_conn)

    def _ensure_flow_log_schema(self, db_conn) -> None:
        require_runtime_schema(db_conn)

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

    def _serialize_flow(self, flow_data) -> dict:
        if hasattr(flow_data, "model_dump"):
            return flow_data.model_dump(mode="json")
        if isinstance(flow_data, dict):
            return dict(flow_data)
        return dict(vars(flow_data))

    def _enqueue_batch_sync(self, flows: list) -> bool:
        if not flows:
            return True

        payloads = [self._serialize_flow(flow) for flow in flows]
        payload_json = self._payload_json(payloads)
        batch_id = self._batch_id_from_payload_json(payload_json)
        first = payloads[0]
        conn = get_db_connection()
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            self._enforce_backpressure(conn, len(payloads))
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO flow_ingest_batches (
                    source_type,
                    source_id,
                    organization_id,
                    batch_id,
                    batch_json,
                    flow_count,
                    status,
                    available_at
                ) VALUES (%s, %s, %s, %s, %s, %s, 'pending', UTC_TIMESTAMP())
                """,
                (
                    str(first.get("source_type") or "agent"),
                    str(first.get("agent_id") or "") or None,
                    str(first.get("organization_id") or "") or None,
                    batch_id,
                    payload_json,
                    len(payloads),
                ),
            )
            conn.commit()
            self._increment_metric("buffered_batches_total")
            self._increment_metric("buffered_flows_total")
            self._set_metric("last_batch_size", len(payloads))
            self._set_metric("last_error", None)
            metrics_service.increment("flow_buffered_batches_total")
            metrics_service.increment("flow_buffered_flows_total", amount=len(payloads))
            self._refresh_queue_depth(conn)
            return True
        except FlowQueueBackpressureError:
            if conn:
                conn.rollback()
            self._increment_metric("backpressure_rejections_total")
            self._increment_metric("dropped_flows_total", len(payloads))
            self._set_metric("last_error", "enqueue_backpressure")
            metrics_service.increment("flow_backpressure_rejections_total")
            metrics_service.increment("flow_dropped_flows_total", amount=len(payloads), reason="backpressure")
            self._refresh_queue_depth(conn)
            raise
        except mysql.connector.Error as exc:
            if conn:
                conn.rollback()
            if int(getattr(exc, "errno", 0) or 0) == 1062:
                self._increment_metric("deduplicated_batches_total")
                self._increment_metric("deduplicated_flows_total", len(payloads))
                self._set_metric("last_batch_size", len(payloads))
                self._set_metric("last_error", None)
                metrics_service.increment("flow_deduplicated_batches_total")
                metrics_service.increment("flow_deduplicated_flows_total", amount=len(payloads))
                self._refresh_queue_depth(conn)
                return True
            logger.exception("Failed to enqueue flow batch with %s flow(s).", len(flows))
            self._increment_metric("dropped_flows_total", len(payloads))
            self._set_metric("last_error", "enqueue_failure")
            metrics_service.increment("flow_dropped_flows_total", amount=len(payloads), reason="enqueue_failure")
            metrics_service.increment("flow_enqueue_failures_total")
            self._refresh_queue_depth(conn)
            return False
        except Exception:
            if conn:
                conn.rollback()
            logger.exception("Failed to enqueue flow batch with %s flow(s).", len(flows))
            self._increment_metric("dropped_flows_total", len(payloads))
            self._set_metric("last_error", "enqueue_failure")
            metrics_service.increment("flow_dropped_flows_total", amount=len(payloads), reason="enqueue_failure")
            metrics_service.increment("flow_enqueue_failures_total")
            self._refresh_queue_depth(conn)
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    async def buffer_flows(self, flows: list) -> bool:
        return await asyncio.to_thread(self._enqueue_batch_sync, list(flows))

    async def buffer_flow(self, flow_data):
        return await self.buffer_flows([flow_data])

    def _claim_pending_batches_sync(self, limit: int) -> list[dict]:
        conn = get_db_connection()
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                UPDATE flow_ingest_batches q
                LEFT JOIN worker_heartbeats h
                  ON h.worker_id = q.claimed_by
                 AND h.worker_type = %s
                SET
                    q.status = 'pending',
                    q.claimed_by = NULL,
                    q.claimed_at = NULL,
                    q.available_at = UTC_TIMESTAMP()
                WHERE q.status = 'processing'
                  AND q.claimed_at IS NOT NULL
                  AND q.claimed_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s SECOND)
                  AND (
                      h.last_seen IS NULL
                      OR h.last_seen < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s SECOND)
                  )
                """,
                (
                    FLOW_WORKER_TYPE,
                    max(int(settings.FLOW_INGEST_CLAIM_TTL_SECONDS or 120), 1),
                    max(int(settings.FLOW_WORKER_ALIVE_SECONDS or 15), 1),
                ),
            )
            recovered_claims = int(cursor.rowcount or 0)
            if recovered_claims:
                metrics_service.increment("flow_stale_claims_recovered_total", amount=recovered_claims)

            cursor.execute(
                """
                SELECT id
                FROM flow_ingest_batches
                WHERE status = 'pending'
                  AND available_at <= UTC_TIMESTAMP()
                ORDER BY available_at ASC, created_at ASC
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (max(int(limit or 1), 1),),
            )
            candidate_ids = [int(row["id"]) for row in cursor.fetchall() or []]
            if not candidate_ids:
                conn.commit()
                self._refresh_queue_depth(conn)
                return []

            placeholders = ",".join(["%s"] * len(candidate_ids))
            cursor.execute(
                f"""
                UPDATE flow_ingest_batches
                SET
                    status = 'processing',
                    claimed_by = %s,
                    claimed_at = UTC_TIMESTAMP(),
                    attempt_count = attempt_count + 1
                WHERE id IN ({placeholders})
                  AND status = 'pending'
                  AND available_at <= UTC_TIMESTAMP()
                """,
                (self._worker_id, *candidate_ids),
            )

            conn.commit()
            if not int(cursor.rowcount or 0):
                self._refresh_queue_depth(conn)
                return []

            cursor.execute(
                f"""
                SELECT id, batch_id, batch_json, flow_count, attempt_count, source_id, source_type, organization_id
                FROM flow_ingest_batches
                WHERE claimed_by = %s
                  AND status = 'processing'
                  AND id IN ({placeholders})
                ORDER BY created_at ASC
                """,
                (self._worker_id, *candidate_ids),
            )
            rows = cursor.fetchall() or []
            self._refresh_queue_depth(conn)
            return rows
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _mark_batch_processed_on_connection(self, cursor, batch_id: int) -> None:
        cursor.execute(
            """
            UPDATE flow_ingest_batches
            SET
                status = 'processed',
                claimed_by = NULL,
                claimed_at = NULL,
                processed_at = UTC_TIMESTAMP(),
                last_error = NULL
            WHERE id = %s
              AND status = 'processing'
              AND claimed_by = %s
            """,
            (batch_id, self._worker_id),
        )
        if int(cursor.rowcount or 0) != 1:
            raise RuntimeError(f"Unable to acknowledge claimed flow batch {batch_id}.")

    def _mark_batch_processed_sync(self, batch_id: int) -> None:
        conn = get_db_connection()
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            cursor = conn.cursor()
            self._mark_batch_processed_on_connection(cursor, batch_id)
            conn.commit()
            self._refresh_queue_depth(conn)
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _mark_batch_retry_sync(self, batch_id: int, error_text: str) -> bool:
        conn = get_db_connection()
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT attempt_count
                FROM flow_ingest_batches
                WHERE id = %s
                LIMIT 1
                """,
                (batch_id,),
            )
            row = cursor.fetchone() or {}
            attempt_count = int(row.get("attempt_count") or 0)
            max_attempts = max(int(settings.FLOW_INGEST_MAX_ATTEMPTS or 5), 1)
            normalized_error = (error_text or "flow_worker_failure")[:2048]

            if attempt_count >= max_attempts:
                cursor.execute(
                    """
                    UPDATE flow_ingest_batches
                    SET
                        status = 'deadletter',
                        claimed_by = NULL,
                        claimed_at = NULL,
                        last_error = %s
                    WHERE id = %s
                    """,
                    (normalized_error, batch_id),
                )
                deadlettered = True
            else:
                backoff_seconds = max(int(settings.FLOW_INGEST_RETRY_SECONDS or 5), 1) * max(attempt_count, 1)
                next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=backoff_seconds)
                cursor.execute(
                    """
                    UPDATE flow_ingest_batches
                    SET
                        status = 'pending',
                        claimed_by = NULL,
                        claimed_at = NULL,
                        available_at = %s,
                        last_error = %s
                    WHERE id = %s
                    """,
                    (self._mysql_timestamp(next_attempt_at), normalized_error, batch_id),
                )
                deadlettered = False

            conn.commit()
            self._refresh_queue_depth(conn)
            return deadlettered
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _touch_worker_heartbeat_sync(self) -> None:
        conn = get_db_connection()
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO worker_heartbeats (worker_id, worker_type, last_seen)
                VALUES (%s, %s, UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    worker_type = VALUES(worker_type),
                    last_seen = VALUES(last_seen)
                """,
                (self._worker_id, FLOW_WORKER_TYPE),
            )
            conn.commit()
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _clear_worker_heartbeat_sync(self) -> None:
        conn = get_db_connection()
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM worker_heartbeats WHERE worker_id = %s", (self._worker_id,))
            conn.commit()
        except Exception:
            if conn:
                conn.rollback()
            logger.exception("Failed to clear flow worker heartbeat for %s.", self._worker_id)
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    async def _worker_heartbeat_loop(self) -> None:
        interval = max(float(settings.FLOW_WORKER_HEARTBEAT_SECONDS or 5.0), 1.0)
        while True:
            try:
                await asyncio.to_thread(self._touch_worker_heartbeat_sync)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._set_metric("last_error", "flow_worker_heartbeat_failure")
                metrics_service.increment("flow_worker_heartbeat_failures_total")
                logger.exception("Flow worker heartbeat update failed.")
            await asyncio.sleep(interval)

    def _deserialize_batch(self, queue_record: dict) -> list[FlowBase]:
        raw_payload = json.loads(queue_record.get("batch_json") or "[]")
        if not isinstance(raw_payload, list):
            raise ValueError("Queued flow batch payload must be a list")
        return list(FLOW_BATCH_ADAPTER.validate_python(raw_payload))

    async def _collect_queue_batch(self) -> list[dict]:
        claim_limit = max(int(settings.FLOW_WORKER_CLAIM_LIMIT or 10), 1)
        claimed = await asyncio.to_thread(self._claim_pending_batches_sync, claim_limit)
        if claimed:
            last_batch_id = int(claimed[-1]["id"])
            self._set_metric("last_claimed_batch_id", last_batch_id)
        return claimed

    async def _emit_realtime_events(self, events_to_emit: list[tuple[str, dict]]) -> None:
        started_at = time.perf_counter()
        for event_name, payload in events_to_emit:
            await emit_event(event_name, payload)
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        self._set_metric("last_emit_duration_ms", duration_ms)
        self._increment_metric("emitted_events_total", len(events_to_emit))
        metrics_service.observe("flow_emit_duration_ms", duration_ms)
        metrics_service.increment("flow_emitted_events_total", amount=len(events_to_emit))

    def _ensure_processing_ready(self, conn) -> None:
        if self._schema_ready:
            return

        require_runtime_schema(conn)
        self._schema_ready = True

    async def flow_writer_worker(self):
        """Async worker to persist durable flow batches and trigger detection."""
        self._set_metric("worker_mode", str(settings.FLOW_WORKER_MODE or "embedded"))
        heartbeat_task = asyncio.create_task(self._worker_heartbeat_loop())
        try:
            while True:
                try:
                    claimed_batches = await self._collect_queue_batch()
                    if not claimed_batches:
                        await asyncio.sleep(max(float(settings.FLOW_WORKER_POLL_SECONDS or 1.0), 0.1))
                        continue

                    for queue_record in claimed_batches:
                        queue_batch_id = int(queue_record["id"])
                        try:
                            self._set_metric("last_batch_size", int(queue_record.get("flow_count") or 0))
                            persist_started_at = time.perf_counter()
                            processing_result = await asyncio.to_thread(self._sync_process_claimed_batch, queue_record)
                            events_to_emit = list(processing_result.get("events_to_emit") or [])
                            processed_flows = max(int(processing_result.get("flow_count") or 0), 0)
                            persist_duration_ms = round((time.perf_counter() - persist_started_at) * 1000, 2)
                            self._set_metric("last_persist_duration_ms", persist_duration_ms)
                            self._set_metric("last_processed_at", datetime.now(timezone.utc).isoformat())
                            self._set_metric("last_error", None)
                            self._increment_metric("processed_batches_total")
                            self._increment_metric("processed_flows_total", processed_flows)
                            metrics_service.increment("flow_processed_batches_total")
                            metrics_service.increment("flow_processed_flows_total", amount=processed_flows)
                            metrics_service.observe("flow_persist_duration_ms", persist_duration_ms)

                            if events_to_emit:
                                try:
                                    await self._emit_realtime_events(events_to_emit)
                                except Exception:
                                    self._set_metric("last_error", "flow_emit_failure")
                                    metrics_service.increment("flow_emit_failures_total")
                                    logger.exception(
                                        "Flow worker failed while emitting realtime events for batch %s.",
                                        queue_batch_id,
                                    )
                        except Exception as exc:
                            self._increment_metric("failed_batches_total")
                            self._set_metric("last_error", "flow_worker_failure")
                            metrics_service.increment("flow_failed_batches_total")
                            logger.exception("Flow worker failed while processing queued batch %s.", queue_batch_id)
                            deadlettered = await asyncio.to_thread(self._mark_batch_retry_sync, queue_batch_id, str(exc))
                            if deadlettered:
                                self._increment_metric("deadletter_batches_total")
                                metrics_service.increment("flow_deadletter_batches_total")
                            else:
                                self._increment_metric("requeued_batches_total")
                                metrics_service.increment("flow_requeued_batches_total")
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._increment_metric("failed_batches_total")
                    self._set_metric("last_error", "flow_worker_claim_failure")
                    metrics_service.increment("flow_failed_batches_total", reason="claim_failure")
                    logger.exception("Flow worker failed while claiming queued flow batches.")
                    await asyncio.sleep(max(float(settings.FLOW_WORKER_POLL_SECONDS or 1.0), 0.1))
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
            await asyncio.to_thread(self._clear_worker_heartbeat_sync)
            self._refresh_queue_depth()

    async def _persist_batch(self, batch):
        """No longer used directly, superseded by _sync_persist_batch + to_thread."""
        events_to_emit = await asyncio.to_thread(self._sync_persist_batch, batch)
        for event_name, payload in events_to_emit:
            await emit_event(event_name, payload)

    def _persist_batch_on_connection(self, conn, cursor, batch) -> list[tuple[str, dict]]:
        events_to_emit = []
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

            cursor.execute(
                """
                INSERT INTO flow_logs (
                    organization_id, src_ip, dst_ip, src_port, dst_port,
                    protocol, start_time, last_seen, packet_count, byte_count,
                    duration, average_packet_size, domain, sni, src_mac, dst_mac,
                    network_scope, internal_device_ip, external_endpoint_ip, session_id,
                    application, agent_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
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
                ),
            )

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

                cursor.execute(
                    """
                    INSERT INTO device_risks (device_id, current_score, risk_level, reasons)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        current_score = VALUES(current_score),
                        risk_level = VALUES(risk_level),
                        reasons = VALUES(reasons)
                    """,
                    (
                        sanitized.internal_device_ip,
                        report["score"],
                        report["severity"],
                        ",".join(report["reasons"]),
                    ),
                )

            if sanitized.internal_device_ip and report["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                cursor.execute(
                    """
                    INSERT INTO alerts (organization_id, device_ip, severity, risk_score, breakdown_json)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        org_id,
                        sanitized.internal_device_ip,
                        report["severity"],
                        report["score"],
                        json.dumps(breakdown),
                    ),
                )

            events_to_emit.append(
                (
                    "packet_event",
                    {
                        "organization_id": org_id,
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
                )
            )

            if report["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                events_to_emit.append(
                    (
                        "alert_event",
                        {
                            "organization_id": org_id,
                            "id": f"alert-{id(sanitized)}",
                            "severity": report["severity"],
                            "score": report["score"],
                            "message": breakdown.get("message") or ", ".join(report["reasons"]) or "Suspicious activity detected",
                            "src_ip": sanitized.src_ip,
                            "application": application,
                            "time": str(self._mysql_timestamp(sanitized.last_seen) or ""),
                        },
                    )
                )

        return events_to_emit

    def _sync_persist_batch(self, batch) -> list[tuple[str, dict]]:
        """Synchronous version of persist_batch to be run in a thread."""
        conn = get_db_connection()
        if not conn:
            self._set_metric("last_error", "db_connection_unavailable")
            metrics_service.increment("flow_db_connection_failures_total")
            return []
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            
            if not system_service.is_monitoring_enabled(conn):
                logger.debug("Monitoring disabled, dropping %s buffered flow(s)", len(batch))
                metrics_service.increment("flow_batches_skipped_total", reason="monitoring_disabled")
                return []

            cursor = conn.cursor(dictionary=True)
            events_to_emit = self._persist_batch_on_connection(conn, cursor, batch)
            conn.commit()
            return events_to_emit
        finally:
            if cursor:
                cursor.close()
            conn.close()
            self._refresh_queue_depth()

    def _sync_process_claimed_batch(self, queue_record: dict) -> dict:
        conn = get_db_connection()
        if not conn:
            self._set_metric("last_error", "db_connection_unavailable")
            metrics_service.increment("flow_db_connection_failures_total")
            raise RuntimeError("Database connection unavailable while processing queued flow batch.")

        batch_id = int(queue_record["id"])
        batch = self._deserialize_batch(queue_record)
        cursor = None
        try:
            self._ensure_processing_ready(conn)
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT status, claimed_by
                FROM flow_ingest_batches
                WHERE id = %s
                LIMIT 1
                FOR UPDATE
                """,
                (batch_id,),
            )
            claimed_row = cursor.fetchone() or {}
            if str(claimed_row.get("status") or "").strip().lower() != "processing":
                raise RuntimeError(f"Claimed flow batch {batch_id} is no longer in processing state.")
            if str(claimed_row.get("claimed_by") or "").strip() != self._worker_id:
                raise RuntimeError(f"Claimed flow batch {batch_id} is no longer owned by worker {self._worker_id}.")

            if not batch:
                self._mark_batch_processed_on_connection(cursor, batch_id)
                conn.commit()
                return {"events_to_emit": [], "flow_count": 0}

            if not system_service.is_monitoring_enabled(conn):
                logger.debug("Monitoring disabled, dropping %s buffered flow(s)", len(batch))
                metrics_service.increment("flow_batches_skipped_total", reason="monitoring_disabled")
                self._mark_batch_processed_on_connection(cursor, batch_id)
                conn.commit()
                return {"events_to_emit": [], "flow_count": len(batch)}

            events_to_emit = self._persist_batch_on_connection(conn, cursor, batch)
            self._mark_batch_processed_on_connection(cursor, batch_id)
            conn.commit()
            return {"events_to_emit": events_to_emit, "flow_count": len(batch)}
        except Exception:
            conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            conn.close()
            self._refresh_queue_depth()

    def get_flow_logs(
        self,
        db_conn,
        organization_id: str,
        limit: int = 50,
        offset: int = 0,
        src_ip: str = None,
        dst_ip: str = None,
        application: str = None,
        severity: str = None,
        search: str = None,
    ) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = [organization_id]
            where_clauses = ["organization_id = %s"]

            if src_ip:
                where_clauses.append("src_ip = %s")
                params.append(src_ip)
            if dst_ip:
                where_clauses.append("dst_ip = %s")
                params.append(dst_ip)
            if application:
                where_clauses.append("application = %s")
                params.append(application)
            if severity:
                # We need to join with device_risks or use alert status
                # For now, let's just filter by a potential severity column if we add it, 
                # but typically severity is computed. Let's filter by application/IP for now.
                pass
            if search:
                where_clauses.append("(src_ip LIKE %s OR dst_ip LIKE %s OR domain LIKE %s OR sni LIKE %s OR application LIKE %s)")
                search_param = f"%{search}%"
                params.extend([search_param] * 5)

            where_str = " AND ".join(where_clauses)
            
            # Count total
            count_sql = f"SELECT COUNT(*) as total FROM flow_logs WHERE {where_str}"
            cursor.execute(count_sql, tuple(params))
            total = cursor.fetchone()["total"]

            # Fetch data
            data_sql = f"""
                SELECT * FROM flow_logs 
                WHERE {where_str} 
                ORDER BY last_seen DESC 
                LIMIT %s OFFSET %s
            """
            params.extend([limit, offset])
            cursor.execute(data_sql, tuple(params))
            rows = cursor.fetchall()

            # Format rows
            for row in rows:
                row["last_seen"] = self._mysql_timestamp(row["last_seen"])
                row["start_time"] = self._mysql_timestamp(row["start_time"])
                row["host"] = row.get("sni") or row.get("domain") or ""
                if (row.get("application") or "") in {"", "Other", "Unknown"}:
                    row["application"] = application_service.classify_app(row)

            return {"total": total, "results": rows}
        finally:
            cursor.close()

    def get_log_stats(self, db_conn, organization_id: str) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        try:
            # Top Applications
            cursor.execute(
                """
                SELECT
                    COALESCE(NULLIF(application, ''), 'Other') AS application,
                    COUNT(*) AS count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes
                FROM flow_logs 
                WHERE organization_id = %s 
                GROUP BY application 
                ORDER BY bandwidth_bytes DESC, count DESC 
                LIMIT 5
                """,
                (organization_id,),
            )
            top_apps = cursor.fetchall()

            # Volume over time (last 24h)
            cursor.execute(
                """
                SELECT
                    DATE_FORMAT(last_seen, '%%Y-%%m-%%d %%H:00:00') AS hour,
                    COUNT(*) AS count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes
                FROM flow_logs 
                WHERE organization_id = %s AND last_seen > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY hour 
                ORDER BY hour ASC
                """,
                (organization_id,),
            )
            volume_trend = cursor.fetchall()

            return {
                "top_apps": top_apps,
                "volume_trend": volume_trend,
            }
        finally:
            cursor.close()

flow_service = FlowService()
