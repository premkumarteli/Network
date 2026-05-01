from app.services.audit_service import AuditService


class FakeCursor:
    def __init__(self):
        self.executed = []
        self.closed = False

    def execute(self, query, params=None):
        self.executed.append((" ".join(query.strip().split()), params or ()))

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def test_log_audit_event_uses_auto_increment_id(monkeypatch):
    fake_conn = FakeConnection()
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: fake_conn)

    service = AuditService()
    service._log_audit_event("default-org-id", "admin", "agent_registration", "agent_id: AGENT-1")

    assert fake_conn.commits == 1
    assert fake_conn.closed is True
    assert fake_conn.cursor_obj.closed is True

    query, params = fake_conn.cursor_obj.executed[0]
    assert "INSERT INTO audit_logs (organization_id, username, action, details, created_at)" in query
    assert len(params) == 5
    assert params[:4] == (
        "default-org-id",
        "admin",
        "agent_registration",
        "agent_id: AGENT-1",
    )
