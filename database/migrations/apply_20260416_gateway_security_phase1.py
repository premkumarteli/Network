from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.session import get_db_connection


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


def main() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    applied: list[str] = []
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_credentials (
                gateway_id VARCHAR(100) NOT NULL,
                key_version INT NOT NULL,
                secret_salt VARCHAR(64) NOT NULL,
                secret_hash CHAR(64) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                rotated_at DATETIME NULL,
                last_used_at DATETIME NULL,
                PRIMARY KEY (gateway_id, key_version),
                INDEX idx_gateway_credentials_status (status)
            )
            """
        )
        applied.append("gateway_credentials")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_request_nonces (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                gateway_id VARCHAR(100) NOT NULL,
                key_version INT NOT NULL,
                nonce VARCHAR(64) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                UNIQUE KEY uq_gateway_nonce (gateway_id, key_version, nonce),
                INDEX idx_gateway_nonce_expires_at (expires_at)
            )
            """
        )
        applied.append("gateway_request_nonces")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS gateways (
                gateway_id VARCHAR(100) PRIMARY KEY,
                organization_id CHAR(36) NULL,
                hostname VARCHAR(100) DEFAULT 'Unknown',
                capture_mode VARCHAR(50) DEFAULT 'promiscuous',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        applied.append("gateways")

        if not column_exists(cursor, "gateways", "organization_id"):
            cursor.execute("ALTER TABLE gateways ADD COLUMN organization_id CHAR(36) NULL AFTER gateway_id")
            applied.append("gateways.organization_id")
        if not column_exists(cursor, "gateways", "created_at"):
            cursor.execute("ALTER TABLE gateways ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER capture_mode")
            applied.append("gateways.created_at")

        conn.commit()
        print("Applied gateway security hardening phase 1 migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
