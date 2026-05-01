from __future__ import annotations

import sys
from pathlib import Path

from mysql.connector import Error

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.session import get_db_connection


DUPLICATE_COLUMN_ERROR = 1060
DUPLICATE_KEY_ERROR = 1061


def table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        LIMIT 1
        """,
        (table_name,),
    )
    return cursor.fetchone() is not None


def column_exists(cursor, table_name: str, column_name: str) -> bool:
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


def index_exists(cursor, table_name: str, index_name: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND index_name = %s
        LIMIT 1
        """,
        (table_name, index_name),
    )
    return cursor.fetchone() is not None


def main() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    applied: list[str] = []

    def _execute(sql: str, label: str, *, ignore_errnos: tuple[int, ...] = ()) -> None:
        try:
            cursor.execute(sql)
            applied.append(label)
        except Error as exc:
            if exc.errno in ignore_errnos:
                return
            raise

    try:
        if not table_exists(cursor, "flow_ingest_batches"):
            raise RuntimeError("flow_ingest_batches is missing. Apply phase 3 migration first.")

        if not column_exists(cursor, "flow_ingest_batches", "batch_id"):
            _execute(
                "ALTER TABLE flow_ingest_batches ADD COLUMN batch_id CHAR(64) NULL AFTER organization_id",
                "flow_ingest_batches.batch_id",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )

        cursor.execute(
            """
            UPDATE flow_ingest_batches
            SET batch_id = SHA2(batch_json, 256)
            WHERE batch_id IS NULL OR batch_id = ''
            """
        )
        if cursor.rowcount:
            applied.append("flow_ingest_batches.batch_id_backfill")

        _execute(
            "ALTER TABLE flow_ingest_batches MODIFY COLUMN batch_id CHAR(64) NOT NULL",
            "flow_ingest_batches.batch_id_not_null",
        )

        if not index_exists(cursor, "flow_ingest_batches", "uniq_flow_ingest_batch_id"):
            _execute(
                "CREATE UNIQUE INDEX uniq_flow_ingest_batch_id ON flow_ingest_batches (batch_id)",
                "flow_ingest_batches.uniq_flow_ingest_batch_id",
                ignore_errnos=(DUPLICATE_KEY_ERROR,),
            )

        if not table_exists(cursor, "worker_heartbeats"):
            cursor.execute(
                """
                CREATE TABLE worker_heartbeats (
                    worker_id VARCHAR(100) PRIMARY KEY,
                    worker_type VARCHAR(32) NOT NULL,
                    last_seen DATETIME NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_worker_heartbeats_type_seen (worker_type, last_seen)
                )
                """
            )
            applied.append("worker_heartbeats")
        elif not index_exists(cursor, "worker_heartbeats", "idx_worker_heartbeats_type_seen"):
            _execute(
                "CREATE INDEX idx_worker_heartbeats_type_seen ON worker_heartbeats (worker_type, last_seen)",
                "worker_heartbeats.idx_worker_heartbeats_type_seen",
                ignore_errnos=(DUPLICATE_KEY_ERROR,),
            )

        conn.commit()
        print("Applied flow ingest hardening phase 4 migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
