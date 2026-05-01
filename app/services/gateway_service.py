from __future__ import annotations

from ..db.session import require_runtime_schema


class GatewayService:
    def __init__(self) -> None:
        self._schema_ready = False

    def _column_exists(self, cursor, table_name: str, column_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND column_name = %s
            LIMIT 1
            """,
            (table_name, column_name),
        )
        return cursor.fetchone() is not None

    def ensure_table(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def upsert_gateway(
        self,
        db_conn,
        *,
        gateway_id: str,
        organization_id: str | None,
        hostname: str | None,
        capture_mode: str | None,
    ) -> None:
        if not gateway_id:
            return

        self.ensure_table(db_conn)

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gateways (gateway_id, organization_id, hostname, capture_mode, created_at, last_seen)
                VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    organization_id = COALESCE(VALUES(organization_id), organization_id),
                    hostname = VALUES(hostname),
                    capture_mode = VALUES(capture_mode),
                    last_seen = UTC_TIMESTAMP()
                """,
                (
                    gateway_id,
                    organization_id,
                    hostname or "Unknown",
                    capture_mode or "promiscuous",
                ),
            )
            db_conn.commit()
        finally:
            cursor.close()


gateway_service = GatewayService()
