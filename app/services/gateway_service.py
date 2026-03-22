from __future__ import annotations


class GatewayService:
    def ensure_table(self, db_conn) -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS gateways (
                    gateway_id VARCHAR(100) PRIMARY KEY,
                    hostname VARCHAR(100) DEFAULT 'Unknown',
                    capture_mode VARCHAR(50) DEFAULT 'promiscuous',
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            db_conn.commit()
        finally:
            cursor.close()

    def upsert_gateway(self, db_conn, gateway_id: str, hostname: str | None, capture_mode: str | None) -> None:
        if not gateway_id:
            return

        self.ensure_table(db_conn)

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gateways (gateway_id, hostname, capture_mode, last_seen)
                VALUES (%s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                    hostname = VALUES(hostname),
                    capture_mode = VALUES(capture_mode),
                    last_seen = NOW()
                """,
                (
                    gateway_id,
                    hostname or "Unknown",
                    capture_mode or "promiscuous",
                ),
            )
            db_conn.commit()
        finally:
            cursor.close()


gateway_service = GatewayService()
