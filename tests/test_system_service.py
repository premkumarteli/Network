from pathlib import Path

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
        if self.query.startswith("SHOW TABLES LIKE"):
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

