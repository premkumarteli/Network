import os
import time
from pathlib import Path

from app.db import session as db_session
from app.services.system_service import SystemService


class FakeCursor:
    def __init__(self, tables):
        self.tables = tables
        self.query = ""
        self.params = ()
        self.closed = False
        self.results = []

    def execute(self, query, params=None):
        self.query = " ".join(query.strip().split())
        self.params = params or ()
        if "FROM information_schema.tables" in self.query:
            _, table_name = self.params
            runtime_tables = set(db_session.REQUIRED_RUNTIME_TABLES) | set(self.tables.keys())
            self.results = [{"count": 1 if table_name in runtime_tables else 0}]
        elif "FROM information_schema.columns" in self.query:
            _, table_name, column_name = self.params
            required_columns = db_session.REQUIRED_RUNTIME_COLUMNS.get(table_name, set())
            self.results = [{"count": 1 if column_name in required_columns else 0}]
        elif "FROM information_schema.statistics" in self.query:
            _, table_name, index_name = self.params
            required_indexes = db_session.REQUIRED_RUNTIME_INDEXES.get(table_name, set())
            self.results = [{"count": 1 if index_name in required_indexes else 0}]
        elif self.query.startswith("SHOW TABLES LIKE"):
            table_name = self.params[0]
            self.results = [{"table": table_name}] if table_name in self.tables else []
        elif self.query.startswith("SELECT COUNT(*) AS count FROM"):
            table_name = self.query.split()[-1]
            self.results = [{"count": len(self.tables.get(table_name, []))}]
        elif self.query.startswith("SELECT * FROM"):
            table_name = self.query.split()[-1]
            self.results = [dict(row) for row in self.tables.get(table_name, [])]
        elif self.query.startswith("DELETE FROM"):
            table_name = self.query.split()[-1]
            self.tables[table_name] = []
            self.results = []
        elif self.query.startswith("ALTER TABLE"):
            self.results = []
        elif "INSERT INTO system_settings" in self.query:
            self.results = []
        elif "CREATE TABLE IF NOT EXISTS" in self.query:
            self.results = []
        else:
            raise AssertionError(f"Unexpected query: {self.query}")

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return list(self.results)

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, tables):
        self.tables = tables
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, dictionary=False):
        return FakeCursor(self.tables)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_backup_and_reset_runtime_data_exports_csv_and_clears_rows(tmp_path):
    tables = {
        "flow_logs": [{"id": 1, "src_ip": "10.0.0.2", "byte_count": 100}],
        "alerts": [{"id": 1, "device_ip": "10.0.0.2", "severity": "HIGH"}],
        "devices": [{"id": 1, "ip": "10.0.0.2", "hostname": "HOST"}],
        "device_aliases": [],
        "device_risks": [{"device_id": "10.0.0.2", "risk_level": "HIGH"}],
        "managed_devices": [],
        "audit_logs": [{"id": 1, "action": "scan"}],
    }
    conn = FakeConnection(tables)
    service = SystemService(backup_root=Path(tmp_path))

    result = service.backup_and_reset_runtime_data(conn, reason="test")

    assert result["backup"]["created"] is True
    assert result["backup"]["row_count"] == 5
    assert result["backup"]["backup_dir"] is not None
    backup_dir = Path(result["backup"]["backup_dir"])
    assert (backup_dir / "flow_logs.csv").exists()
    assert (backup_dir / "alerts.csv").exists()
    assert (backup_dir / "summary.csv").exists()
    assert all(len(rows) == 0 for rows in tables.values())
    assert conn.commits >= 1


def test_clear_runtime_data_removes_volatile_runtime_files(tmp_path):
    tables = {
        "flow_logs": [{"id": 1, "src_ip": "10.0.0.2", "byte_count": 100}],
        "alerts": [],
        "devices": [],
        "device_aliases": [],
        "device_risks": [],
        "managed_devices": [],
        "audit_logs": [],
    }
    conn = FakeConnection(tables)
    service = SystemService(backup_root=Path(tmp_path))
    volatile_file = Path(tmp_path) / "runtime" / "agent" / "device_inventory.json"
    volatile_file.parent.mkdir(parents=True, exist_ok=True)
    volatile_file.write_text('{"10.0.0.2": {"hostname": "old"}}', encoding="utf-8")
    service._volatile_runtime_files = (volatile_file,)

    service.clear_runtime_data(conn)

    assert not volatile_file.exists()


def test_clear_runtime_data_keeps_persistent_inspection_policy_rows(tmp_path):
    tables = {
        "flow_logs": [],
        "alerts": [],
        "devices": [],
        "device_aliases": [],
        "device_risks": [],
        "managed_devices": [],
        "web_events": [{"id": 1, "page_url": "https://example.com"}],
        "inspection_policies": [{"agent_id": "AGENT-1", "device_ip": "10.0.0.5"}],
        "audit_logs": [],
    }
    conn = FakeConnection(tables)
    service = SystemService(backup_root=Path(tmp_path))

    service.clear_runtime_data(conn)

    assert tables["web_events"] == []
    assert tables["inspection_policies"] == [{"agent_id": "AGENT-1", "device_ip": "10.0.0.5"}]


def test_cleanup_old_backups_prunes_expired_directories(tmp_path):
    backup_root = Path(tmp_path)
    service = SystemService(backup_root=backup_root)

    expired = backup_root / "20240101_010101_expired"
    recent = backup_root / "20241231_235959_recent"
    expired.mkdir(parents=True, exist_ok=True)
    recent.mkdir(parents=True, exist_ok=True)

    now = time.time()
    os.utime(expired, (now - 10 * 24 * 60 * 60, now - 10 * 24 * 60 * 60))
    os.utime(recent, (now - 1 * 24 * 60 * 60, now - 1 * 24 * 60 * 60))

    result = service.cleanup_old_backups(retention_days=7)

    assert result["configured"] is True
    assert result["retention_days"] == 7
    assert result["deleted_count"] == 1
    assert str(expired) in result["deleted_dirs"]
    assert not expired.exists()
    assert recent.exists()

