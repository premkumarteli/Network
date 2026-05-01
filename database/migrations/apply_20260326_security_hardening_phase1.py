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
        user_columns = [
            ("status", "ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active' AFTER role"),
            ("failed_login_count", "ALTER TABLE users ADD COLUMN failed_login_count INT NOT NULL DEFAULT 0 AFTER status"),
            ("locked_until", "ALTER TABLE users ADD COLUMN locked_until DATETIME NULL AFTER failed_login_count"),
            (
                "last_password_change",
                "ALTER TABLE users ADD COLUMN last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP AFTER locked_until",
            ),
        ]
        for column_name, statement in user_columns:
            if not column_exists(cursor, "users", column_name):
                cursor.execute(statement)
                applied.append(f"users.{column_name}")

        cursor.execute(
            """
            UPDATE users
            SET status = COALESCE(NULLIF(status, ''), 'active')
            WHERE status IS NULL OR status = ''
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_credentials (
                agent_id VARCHAR(100) NOT NULL,
                key_version INT NOT NULL,
                secret_salt VARCHAR(64) NOT NULL,
                secret_hash CHAR(64) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                rotated_at DATETIME NULL,
                last_used_at DATETIME NULL,
                PRIMARY KEY (agent_id, key_version),
                INDEX idx_agent_credentials_status (status)
            )
            """
        )
        applied.append("agent_credentials")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_request_nonces (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                agent_id VARCHAR(100) NOT NULL,
                key_version INT NOT NULL,
                nonce VARCHAR(64) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                UNIQUE KEY uq_agent_nonce (agent_id, key_version, nonce),
                INDEX idx_agent_nonce_expires_at (expires_at)
            )
            """
        )
        applied.append("agent_request_nonces")

        cursor.execute(
            """
            UPDATE agents
            SET api_key = NULL
            WHERE api_key IS NOT NULL
            """
        )

        conn.commit()
        print("Applied security hardening phase 1 migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
