from app.db import session as db_session


class _FakeConnection:
    def __init__(self, *, fail_ping: bool = False):
        self.fail_ping = fail_ping
        self.closed = False
        self.ping_calls = 0

    def ping(self, reconnect=True, attempts=1, delay=0):
        self.ping_calls += 1
        if self.fail_ping:
            raise RuntimeError("stale connection")

    def close(self):
        self.closed = True


class _FakePool:
    def __init__(self, connection):
        self.connection = connection
        self.calls = 0

    def get_connection(self):
        self.calls += 1
        return self.connection


class _SchemaCursor:
    def __init__(self, conn):
        self.conn = conn
        self._result = None

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        if "FROM information_schema.tables" in normalized:
            _, table_name = params
            self._result = {"count": 1 if table_name in self.conn.tables else 0}
            return
        if "FROM information_schema.columns" in normalized:
            _, table_name, column_name = params
            self._result = {"count": 1 if column_name in self.conn.columns.get(table_name, set()) else 0}
            return
        if "FROM information_schema.statistics" in normalized:
            _, table_name, index_name = params
            self._result = {"count": 1 if index_name in self.conn.indexes.get(table_name, set()) else 0}
            return
        if normalized.startswith("CREATE TABLE IF NOT EXISTS agent_credentials"):
            self.conn.tables.add("agent_credentials")
            return
        if normalized.startswith("CREATE TABLE IF NOT EXISTS agent_enrollment_requests"):
            self.conn.tables.add("agent_enrollment_requests")
            return
        if normalized.startswith("CREATE TABLE IF NOT EXISTS agent_request_nonces"):
            self.conn.tables.add("agent_request_nonces")
            return
        if normalized.startswith("CREATE TABLE IF NOT EXISTS gateway_credentials"):
            self.conn.tables.add("gateway_credentials")
            return
        if normalized.startswith("CREATE TABLE IF NOT EXISTS gateway_request_nonces"):
            self.conn.tables.add("gateway_request_nonces")
            return
        if normalized.startswith("ALTER TABLE users ADD COLUMN status"):
            self.conn.columns.setdefault("users", set()).add("status")
            return
        if normalized.startswith("ALTER TABLE users ADD COLUMN failed_login_count"):
            self.conn.columns.setdefault("users", set()).add("failed_login_count")
            return
        if normalized.startswith("ALTER TABLE users ADD COLUMN locked_until"):
            self.conn.columns.setdefault("users", set()).add("locked_until")
            return
        if normalized.startswith("ALTER TABLE users ADD COLUMN last_password_change"):
            self.conn.columns.setdefault("users", set()).add("last_password_change")
            return
        raise AssertionError(f"Unexpected query: {normalized}")

    def fetchone(self):
        return self._result

    def close(self):
        return None


class _SchemaConnection:
    def __init__(self):
        self.tables = set()
        self.columns = {"users": set()}
        self.indexes = {}
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, dictionary=False):
        return _SchemaCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        return None


def test_get_db_connection_falls_back_to_direct_connection_when_pool_is_stale(monkeypatch):
    stale = _FakeConnection(fail_ping=True)
    fresh = _FakeConnection()
    fake_pool = _FakePool(stale)

    monkeypatch.setattr(db_session, "_pool", fake_pool)
    monkeypatch.setattr(db_session, "_initialize_pool", lambda force=False: fake_pool)
    monkeypatch.setattr(db_session, "_connect_direct", lambda: fresh)

    conn = db_session.get_db_connection()

    assert conn is fresh
    assert stale.ping_calls == 1
    assert fresh.ping_calls == 1


def test_ensure_security_schema_creates_missing_tables_and_columns(monkeypatch):
    conn = _SchemaConnection()
    monkeypatch.setattr(db_session.settings, "DB_NAME", "network_security")

    result = db_session.ensure_security_schema(conn)

    assert result["ready"] is True
    assert {
        "agent_credentials",
        "agent_request_nonces",
        "gateway_credentials",
        "gateway_request_nonces",
    } <= conn.tables
    assert {
        "status",
        "failed_login_count",
        "locked_until",
        "last_password_change",
    } <= conn.columns["users"]
    assert conn.commits == 1


def test_security_schema_status_reports_missing_objects(monkeypatch):
    conn = _SchemaConnection()
    monkeypatch.setattr(db_session.settings, "DB_NAME", "network_security")

    status = db_session.security_schema_status(conn)

    assert status["ready"] is False
    assert "agent_credentials" in status["missing_tables"]
    assert "gateway_credentials" in status["missing_tables"]
    assert "users.status" in status["missing_columns"]


def test_runtime_schema_status_reports_missing_runtime_objects(monkeypatch):
    conn = _SchemaConnection()
    conn.tables.update({"flow_logs", "devices"})
    monkeypatch.setattr(db_session.settings, "DB_NAME", "network_security")

    status = db_session.runtime_schema_status(conn)

    assert status["ready"] is False
    assert "agents" in status["missing_tables"]
    assert "flow_logs.application" in status["missing_columns"]
    assert "devices.idx_devices_org_last_seen" in status["missing_indexes"]


def test_require_runtime_schema_raises_when_runtime_schema_is_missing(monkeypatch):
    conn = _SchemaConnection()
    monkeypatch.setattr(db_session.settings, "DB_NAME", "network_security")

    try:
        db_session.require_runtime_schema(conn)
        assert False, "Expected runtime schema validation to fail when tables are missing"
    except RuntimeError as exc:
        message = str(exc)
        assert "Runtime schema is incomplete" in message
        assert "agents" in message
