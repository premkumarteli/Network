from __future__ import annotations

import os
import time
from pathlib import Path

import mysql.connector


def _iter_sql_statements(sql: str):
    buffer: list[str] = []
    for raw_line in sql.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue
        buffer.append(raw_line)
        if line.endswith(";"):
            statement = "\n".join(buffer).strip().rstrip(";").strip()
            buffer = []
            if statement:
                yield statement
    trailing = "\n".join(buffer).strip()
    if trailing:
        yield trailing


def _connect_with_retry():
    config = {
        "host": os.environ.get("NETVISOR_DB_HOST", "127.0.0.1"),
        "user": os.environ.get("NETVISOR_DB_USER", "root"),
        "password": os.environ.get("NETVISOR_DB_PASSWORD", ""),
        "connection_timeout": 5,
        "autocommit": False,
    }
    last_error: Exception | None = None
    for _ in range(30):
        try:
            return mysql.connector.connect(**config)
        except mysql.connector.Error as exc:
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"MySQL did not become available for CI initialization: {last_error}")


def main() -> None:
    sql_path = Path(__file__).resolve().parents[1] / "database" / "init.sql"
    statements = list(_iter_sql_statements(sql_path.read_text(encoding="utf-8")))

    conn = _connect_with_retry()
    cursor = conn.cursor()
    try:
        for statement in statements:
            cursor.execute(statement)
        conn.commit()
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
