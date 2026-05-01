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
            cursor.execute(
                """
                CREATE TABLE flow_ingest_batches (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    source_type VARCHAR(16) NOT NULL,
                    source_id VARCHAR(100),
                    organization_id CHAR(36),
                    batch_json LONGTEXT NOT NULL,
                    flow_count INT NOT NULL DEFAULT 1,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    attempt_count INT NOT NULL DEFAULT 0,
                    available_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    claimed_by VARCHAR(100),
                    claimed_at DATETIME NULL,
                    processed_at DATETIME NULL,
                    last_error TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_flow_ingest_status_available (status, available_at, id),
                    INDEX idx_flow_ingest_created_at (created_at),
                    INDEX idx_flow_ingest_source (source_type, source_id, created_at)
                )
                """
            )
            applied.append("flow_ingest_batches")
        else:
            column_sql = {
                "source_type": "ALTER TABLE flow_ingest_batches ADD COLUMN source_type VARCHAR(16) NOT NULL AFTER id",
                "source_id": "ALTER TABLE flow_ingest_batches ADD COLUMN source_id VARCHAR(100) NULL AFTER source_type",
                "organization_id": "ALTER TABLE flow_ingest_batches ADD COLUMN organization_id CHAR(36) NULL AFTER source_id",
                "batch_json": "ALTER TABLE flow_ingest_batches ADD COLUMN batch_json LONGTEXT NOT NULL AFTER organization_id",
                "flow_count": "ALTER TABLE flow_ingest_batches ADD COLUMN flow_count INT NOT NULL DEFAULT 1 AFTER batch_json",
                "status": "ALTER TABLE flow_ingest_batches ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'pending' AFTER flow_count",
                "attempt_count": "ALTER TABLE flow_ingest_batches ADD COLUMN attempt_count INT NOT NULL DEFAULT 0 AFTER status",
                "available_at": "ALTER TABLE flow_ingest_batches ADD COLUMN available_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER attempt_count",
                "claimed_by": "ALTER TABLE flow_ingest_batches ADD COLUMN claimed_by VARCHAR(100) NULL AFTER available_at",
                "claimed_at": "ALTER TABLE flow_ingest_batches ADD COLUMN claimed_at DATETIME NULL AFTER claimed_by",
                "processed_at": "ALTER TABLE flow_ingest_batches ADD COLUMN processed_at DATETIME NULL AFTER claimed_at",
                "last_error": "ALTER TABLE flow_ingest_batches ADD COLUMN last_error TEXT NULL AFTER processed_at",
                "created_at": "ALTER TABLE flow_ingest_batches ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER last_error",
                "updated_at": "ALTER TABLE flow_ingest_batches ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at",
            }
            for column_name, sql in column_sql.items():
                if not column_exists(cursor, "flow_ingest_batches", column_name):
                    _execute(
                        sql,
                        f"flow_ingest_batches.{column_name}",
                        ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
                    )

            index_sql = {
                "idx_flow_ingest_status_available": (
                    "CREATE INDEX idx_flow_ingest_status_available ON flow_ingest_batches (status, available_at, id)"
                ),
                "idx_flow_ingest_created_at": (
                    "CREATE INDEX idx_flow_ingest_created_at ON flow_ingest_batches (created_at)"
                ),
                "idx_flow_ingest_source": (
                    "CREATE INDEX idx_flow_ingest_source ON flow_ingest_batches (source_type, source_id, created_at)"
                ),
            }
            for index_name, sql in index_sql.items():
                if not index_exists(cursor, "flow_ingest_batches", index_name):
                    _execute(sql, f"flow_ingest_batches.{index_name}", ignore_errnos=(DUPLICATE_KEY_ERROR,))

        conn.commit()
        print("Applied flow ingest phase 3 migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
