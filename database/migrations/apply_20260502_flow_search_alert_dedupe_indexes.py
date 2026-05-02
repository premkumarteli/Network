from __future__ import annotations

import sys
from pathlib import Path

from mysql.connector import Error

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.session import get_db_connection


DUPLICATE_KEY_ERROR = 1061


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
    indexes = (
        ("flow_logs", "idx_flow_logs_dst", "CREATE INDEX idx_flow_logs_dst ON flow_logs (dst_ip)"),
        (
            "flow_logs",
            "idx_flow_logs_org_last_seen",
            "CREATE INDEX idx_flow_logs_org_last_seen ON flow_logs (organization_id, last_seen)",
        ),
        (
            "flow_logs",
            "idx_flow_logs_domain_last_seen",
            "CREATE INDEX idx_flow_logs_domain_last_seen ON flow_logs (domain, last_seen)",
        ),
        (
            "alerts",
            "idx_alerts_org_device_severity_time",
            "CREATE INDEX idx_alerts_org_device_severity_time ON alerts (organization_id, device_ip, severity, timestamp)",
        ),
    )

    try:
        for table_name, index_name, sql in indexes:
            if index_exists(cursor, table_name, index_name):
                continue
            try:
                cursor.execute(sql)
                applied.append(f"{table_name}.{index_name}")
            except Error as exc:
                if exc.errno != DUPLICATE_KEY_ERROR:
                    raise
        conn.commit()
        print("Applied flow search and alert dedupe indexes.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
