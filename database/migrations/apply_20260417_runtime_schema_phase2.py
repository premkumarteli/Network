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


def primary_key_columns(cursor, table_name: str) -> list[str]:
    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.key_column_usage
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND constraint_name = 'PRIMARY'
        ORDER BY ordinal_position
        """,
        (table_name,),
    )
    return [row[0] for row in cursor.fetchall() if row and row[0]]


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
        if not column_exists(cursor, "agents", "inspection_metrics_json"):
            _execute(
                "ALTER TABLE agents ADD COLUMN inspection_metrics_json TEXT NULL AFTER inspection_last_error",
                "agents.inspection_metrics_json",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "agents", "cpu_usage"):
            _execute(
                "ALTER TABLE agents ADD COLUMN cpu_usage FLOAT DEFAULT 0.0 AFTER last_seen",
                "agents.cpu_usage",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "agents", "ram_usage"):
            _execute(
                "ALTER TABLE agents ADD COLUMN ram_usage FLOAT DEFAULT 0.0 AFTER cpu_usage",
                "agents.ram_usage",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )

        if not index_exists(cursor, "devices", "idx_devices_org_last_seen"):
            _execute(
                "CREATE INDEX idx_devices_org_last_seen ON devices (organization_id, last_seen)",
                "devices.idx_devices_org_last_seen",
                ignore_errnos=(DUPLICATE_KEY_ERROR,),
            )

        if not index_exists(cursor, "device_ip_history", "idx_device_ip_history_org_last_seen"):
            _execute(
                "CREATE INDEX idx_device_ip_history_org_last_seen ON device_ip_history (organization_id, last_seen)",
                "device_ip_history.idx_device_ip_history_org_last_seen",
                ignore_errnos=(DUPLICATE_KEY_ERROR,),
            )

        if not table_exists(cursor, "managed_devices"):
            cursor.execute(
                """
                CREATE TABLE managed_devices (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    agent_id VARCHAR(100) NOT NULL,
                    organization_id CHAR(36),
                    device_ip VARCHAR(50) NOT NULL,
                    device_mac VARCHAR(50) DEFAULT '-',
                    hostname VARCHAR(100) DEFAULT 'Unknown',
                    os_family VARCHAR(50) DEFAULT 'Unknown',
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_managed_agent_ip_org (agent_id, device_ip, organization_id),
                    UNIQUE KEY uq_managed_ip_org (device_ip, organization_id),
                    INDEX idx_managed_agent_last_seen (agent_id, last_seen)
                )
                """
            )
            applied.append("managed_devices")
        else:
            id_exists = column_exists(cursor, "managed_devices", "id")
            pk_columns = primary_key_columns(cursor, "managed_devices")
            if not id_exists:
                if pk_columns:
                    cursor.execute("ALTER TABLE managed_devices DROP PRIMARY KEY")
                _execute(
                    "ALTER TABLE managed_devices ADD COLUMN id BIGINT NOT NULL AUTO_INCREMENT FIRST",
                    "managed_devices.id",
                    ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
                )
                cursor.execute("ALTER TABLE managed_devices ADD PRIMARY KEY (id)")
            elif pk_columns != ["id"]:
                if pk_columns:
                    cursor.execute("ALTER TABLE managed_devices DROP PRIMARY KEY")
                cursor.execute("ALTER TABLE managed_devices ADD PRIMARY KEY (id)")
                applied.append("managed_devices.primary_key")

            if not index_exists(cursor, "managed_devices", "uq_managed_agent_ip_org"):
                _execute(
                    "CREATE UNIQUE INDEX uq_managed_agent_ip_org ON managed_devices (agent_id, device_ip, organization_id)",
                    "managed_devices.uq_managed_agent_ip_org",
                    ignore_errnos=(DUPLICATE_KEY_ERROR,),
                )
            if not index_exists(cursor, "managed_devices", "uq_managed_ip_org"):
                _execute(
                    "CREATE UNIQUE INDEX uq_managed_ip_org ON managed_devices (device_ip, organization_id)",
                    "managed_devices.uq_managed_ip_org",
                    ignore_errnos=(DUPLICATE_KEY_ERROR,),
                )
            if not index_exists(cursor, "managed_devices", "idx_managed_agent_last_seen"):
                _execute(
                    "CREATE INDEX idx_managed_agent_last_seen ON managed_devices (agent_id, last_seen)",
                    "managed_devices.idx_managed_agent_last_seen",
                    ignore_errnos=(DUPLICATE_KEY_ERROR,),
                )

        if not column_exists(cursor, "gateways", "organization_id"):
            _execute(
                "ALTER TABLE gateways ADD COLUMN organization_id CHAR(36) NULL AFTER gateway_id",
                "gateways.organization_id",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "gateways", "created_at"):
            _execute(
                "ALTER TABLE gateways ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER capture_mode",
                "gateways.created_at",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )

        if not column_exists(cursor, "web_events", "search_query"):
            _execute(
                "ALTER TABLE web_events ADD COLUMN search_query VARCHAR(255) NULL AFTER content_id",
                "web_events.search_query",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "web_events", "confidence_score"):
            _execute(
                "ALTER TABLE web_events ADD COLUMN confidence_score FLOAT DEFAULT 0.0 AFTER snippet_hash",
                "web_events.confidence_score",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "web_events", "event_count"):
            _execute(
                "ALTER TABLE web_events ADD COLUMN event_count INT DEFAULT 1 AFTER confidence_score",
                "web_events.event_count",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "web_events", "risk_level"):
            _execute(
                "ALTER TABLE web_events ADD COLUMN risk_level VARCHAR(20) DEFAULT 'safe' AFTER last_seen",
                "web_events.risk_level",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )
        if not column_exists(cursor, "web_events", "threat_msg"):
            _execute(
                "ALTER TABLE web_events ADD COLUMN threat_msg VARCHAR(255) NULL AFTER risk_level",
                "web_events.threat_msg",
                ignore_errnos=(DUPLICATE_COLUMN_ERROR,),
            )

        conn.commit()
        print("Applied runtime schema phase 2 migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
