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
