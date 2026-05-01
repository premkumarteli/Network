from __future__ import annotations

from pathlib import Path

from agent.security.dpapi import DataProtector
from agent.security.state import ProtectedStateStore


class BrokenProtector(DataProtector):
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        raise ValueError("invalid protected state")


def test_agent_state_store_recovers_from_decryption_failure(tmp_path):
    state_path = Path(tmp_path) / "agent-state.dpapi"
    state_path.write_bytes(b"invalid-state")
    store = ProtectedStateStore(state_path, protector=BrokenProtector())

    loaded = store.load({"agent_credentials": None})

    assert loaded == {"agent_credentials": None}
    assert not state_path.exists()
