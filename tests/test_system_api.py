from __future__ import annotations

import asyncio

from app.api import system as system_api


class _Connection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _run(awaitable):
    return asyncio.run(awaitable)


def test_get_system_status_preserves_flat_and_nested_runtime_fields(monkeypatch):
    conn = _Connection()

    monkeypatch.setattr(system_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(system_api.system_service, "get_runtime_status", lambda _conn: {"active": True, "maintenance_mode": False})
    monkeypatch.setattr(system_api.release_service, "snapshot", lambda: {"release_version": "2026.04.19"})
    monkeypatch.setattr(system_api.system_service, "latest_backup_status", lambda: {"verified": True})
    monkeypatch.setattr(system_api.system_service, "backup_retention_status", lambda: {"configured": True, "retention_days": 30})

    payload = _run(system_api.get_system_status(current_user={"role": "org_admin"}))

    assert payload["active"] is True
    assert payload["maintenance_mode"] is False
    assert payload["runtime"] == {"active": True, "maintenance_mode": False}
    assert payload["release"] == {"release_version": "2026.04.19"}
    assert payload["backup"] == {"verified": True}
    assert payload["backup_retention"] == {"configured": True, "retention_days": 30}
    assert conn.closed is True
