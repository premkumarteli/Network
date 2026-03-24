from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import csv
import socket

import psutil

from ..core.config import settings


class SystemService:
    OPERATIONAL_TABLES = (
        "flow_logs",
        "sessions",
        "external_endpoints",
        "alerts",
        "devices",
        "device_ip_history",
        "device_aliases",
        "device_risks",
        "managed_devices",
        "web_events",
        "audit_logs",
    )

    def __init__(self, backup_root: Optional[Path] = None):
        self.backup_root = Path(backup_root or settings.BACKUP_DIR)
        runtime_root = Path(__file__).resolve().parents[2] / "runtime"
        self._volatile_runtime_files = (
            runtime_root / "agent" / "device_inventory.json",
        )
        self._schema_ready = False

    def ensure_tables(self, db_conn) -> None:
        if self._schema_ready:
            return

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS system_settings (
                    setting_key VARCHAR(100) PRIMARY KEY,
                    setting_value VARCHAR(20) NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    organization_id CHAR(36) NULL,
                    username VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                INSERT INTO system_settings (setting_key, setting_value)
                VALUES ('monitoring_active', 'true')
                ON DUPLICATE KEY UPDATE setting_key = setting_key
                """
            )
            cursor.execute(
                """
                INSERT INTO system_settings (setting_key, setting_value)
                VALUES ('maintenance_mode', 'false')
                ON DUPLICATE KEY UPDATE setting_key = setting_key
                """
            )
            db_conn.commit()
        finally:
            cursor.close()

    def _table_exists(self, cursor, table_name: str) -> bool:
        cursor.execute("SHOW TABLES LIKE %s", (table_name,))
        return cursor.fetchone() is not None

    def _serialize_value(self, value):
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return value

    def _table_count(self, cursor, table_name: str) -> int:
        cursor.execute(f"SELECT COUNT(*) AS count FROM {table_name}")
        row = cursor.fetchone() or {}
        return int(row.get("count") or 0)

    def _export_table_to_csv(self, db_conn, table_name: str, backup_dir: Path) -> int:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()
        finally:
            cursor.close()

        if not rows:
            return 0

        csv_path = backup_dir / f"{table_name}.csv"
        fieldnames = list(rows[0].keys())
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: self._serialize_value(value) for key, value in row.items()})
        return len(rows)

    def backup_runtime_data(self, db_conn, reason: str = "manual") -> dict:
        summary_cursor = db_conn.cursor(dictionary=True)
        try:
            table_counts = {}
            total_rows = 0
            for table_name in self.OPERATIONAL_TABLES:
                if not self._table_exists(summary_cursor, table_name):
                    continue
                row_count = self._table_count(summary_cursor, table_name)
                if row_count > 0:
                    table_counts[table_name] = row_count
                    total_rows += row_count
        finally:
            summary_cursor.close()

        if total_rows == 0:
            return {
                "created": False,
                "backup_dir": None,
                "row_count": 0,
                "tables": {},
            }

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_dir = self.backup_root / f"{timestamp}_{reason}"
        backup_dir.mkdir(parents=True, exist_ok=True)

        exported_tables = {}
        for table_name in table_counts:
            exported_rows = self._export_table_to_csv(db_conn, table_name, backup_dir)
            if exported_rows:
                exported_tables[table_name] = exported_rows

        summary_path = backup_dir / "summary.csv"
        with summary_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["table_name", "row_count"])
            for table_name, row_count in exported_tables.items():
                writer.writerow([table_name, row_count])

        return {
            "created": True,
            "backup_dir": str(backup_dir),
            "row_count": sum(exported_tables.values()),
            "tables": exported_tables,
        }

    def clear_runtime_data(self, db_conn) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        auto_increment_tables = {"flow_logs", "alerts", "devices", "device_ip_history", "device_aliases", "web_events", "audit_logs"}
        try:
            cleared_counts = {}
            for table_name in self.OPERATIONAL_TABLES:
                if not self._table_exists(cursor, table_name):
                    continue
                row_count = self._table_count(cursor, table_name)
                if row_count == 0:
                    continue
                cursor.execute(f"DELETE FROM {table_name}")
                cleared_counts[table_name] = row_count
                if table_name in auto_increment_tables:
                    cursor.execute(f"ALTER TABLE {table_name} AUTO_INCREMENT = 1")
            db_conn.commit()
            self._clear_runtime_files()
            return cleared_counts
        except Exception:
            db_conn.rollback()
            raise
        finally:
            cursor.close()

    def _clear_runtime_files(self) -> None:
        for path in self._volatile_runtime_files:
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                continue

    def backup_and_reset_runtime_data(self, db_conn, reason: str = "manual") -> dict:
        backup = self.backup_runtime_data(db_conn, reason=reason)
        cleared = self.clear_runtime_data(db_conn)
        return {
            "backup": backup,
            "cleared": cleared,
            "message": (
                f"Backed up {backup['row_count']} row(s) and cleared {sum(cleared.values())} runtime row(s)."
                if backup["created"]
                else f"Cleared {sum(cleared.values())} runtime row(s)."
            ),
        }

    def prepare_clean_runtime(self, db_conn, reason: str = "startup") -> dict:
        return self.backup_and_reset_runtime_data(db_conn, reason=reason)

    def _get_setting(self, db_conn, key: str, default: bool) -> bool:
        self.ensure_tables(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT setting_value FROM system_settings WHERE setting_key = %s",
                (key,),
            )
            row = cursor.fetchone()
            if not row:
                return default
            return str(row.get("setting_value", "")).lower() == "true"
        finally:
            cursor.close()

    def _set_setting(self, db_conn, key: str, active: bool) -> None:
        self.ensure_tables(db_conn)
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO system_settings (setting_key, setting_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
                """,
                (key, "true" if active else "false"),
            )
        finally:
            cursor.close()

    def log_action(
        self,
        db_conn,
        username: str,
        action: str,
        details: str,
        organization_id: Optional[str] = None,
    ) -> None:
        self.ensure_tables(db_conn)
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO audit_logs (organization_id, username, action, details)
                VALUES (%s, %s, %s, %s)
                """,
                (organization_id, username or "unknown", action, details),
            )
        finally:
            cursor.close()

    def is_monitoring_enabled(self, db_conn) -> bool:
        return self._get_setting(db_conn, "monitoring_active", True)

    def get_runtime_status(self, db_conn) -> dict:
        return {
            "active": self._get_setting(db_conn, "monitoring_active", True),
            "maintenance_mode": self._get_setting(db_conn, "maintenance_mode", False),
        }

    def get_admin_stats(self, db_conn) -> dict:
        status = self.get_runtime_status(db_conn)
        memory = psutil.virtual_memory()
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except OSError:
            local_ip = "127.0.0.1"

        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "cpu_percent": round(psutil.cpu_percent(), 1),
            "mem_used_mb": round(memory.used / (1024 * 1024), 2),
            "mem_total_mb": round(memory.total / (1024 * 1024), 2),
            "maintenance_mode": status["maintenance_mode"],
        }

    def set_monitoring(
        self,
        db_conn,
        active: bool,
        username: str,
        organization_id: Optional[str] = None,
    ) -> dict:
        self._set_setting(db_conn, "monitoring_active", active)
        self.log_action(
            db_conn,
            username=username,
            action="monitoring_toggle",
            details=f"Monitoring {'enabled' if active else 'disabled'}",
            organization_id=organization_id,
        )
        db_conn.commit()
        return {"status": "success", "message": "Monitoring state updated"}

    def set_maintenance(
        self,
        db_conn,
        active: bool,
        username: str,
        organization_id: Optional[str] = None,
    ) -> dict:
        self._set_setting(db_conn, "maintenance_mode", active)
        self.log_action(
            db_conn,
            username=username,
            action="maintenance_toggle",
            details=f"Maintenance mode {'enabled' if active else 'disabled'}",
            organization_id=organization_id,
        )
        db_conn.commit()
        return {
            "status": "success",
            "message": f"Maintenance mode {'enabled' if active else 'disabled'}",
        }

    def trigger_scan(
        self,
        db_conn,
        username: str,
        organization_id: Optional[str] = None,
    ) -> dict:
        self.log_action(
            db_conn,
            username=username,
            action="force_scan",
            details="Triggered simulated network scan",
            organization_id=organization_id,
        )
        db_conn.commit()
        return {"status": "success", "message": "Network scan triggered (simulation)"}

    def list_logs(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        limit: int = 20,
    ) -> list[dict]:
        self.ensure_tables(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            query = """
                SELECT created_at, username, action, details
                FROM audit_logs
            """
            if organization_id:
                query += " WHERE organization_id = %s OR organization_id IS NULL"
                params.append(organization_id)

            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            cursor.execute(query, tuple(params))

            rows = []
            for row in cursor.fetchall():
                timestamp = row.get("created_at")
                if timestamp and hasattr(timestamp, "strftime"):
                    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                rows.append(
                    {
                        "time": timestamp,
                        "action": row.get("action"),
                        "details": row.get("details") or f"User: {row.get('username')}",
                    }
                )
            return rows
        finally:
            cursor.close()

    def reset_operational_data(
        self,
        db_conn,
        username: str,
        organization_id: Optional[str] = None,
    ) -> dict:
        result = self.backup_and_reset_runtime_data(db_conn, reason="manual_reset")
        return {
            "status": "success",
            "message": result["message"],
            "backup_dir": result["backup"]["backup_dir"],
            "cleared_tables": result["cleared"],
        }


system_service = SystemService()
