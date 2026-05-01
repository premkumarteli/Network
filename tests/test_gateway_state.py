from __future__ import annotations

from pathlib import Path

import pytest

from gateway.security.dpapi import DataProtector
from gateway.security.state import GatewayStateStore


class FakeProtector(DataProtector):
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return b"enc:" + data

    def unprotect(self, data: bytes) -> bytes:
        assert data.startswith(b"enc:")
        return data[4:]


class FakePosixStateStore(GatewayStateStore):
    def __init__(self, path: Path):
        self._modes: dict[Path, int] = {}
        super().__init__(path, platform_name="posix")

    def _chmod_path(self, path: Path, mode: int) -> None:
        self._modes[path] = mode

    def _stat_mode(self, path: Path) -> int:
        return self._modes.get(path, 0o700 if path == self.path.parent else 0o600)


class BrokenPosixStateStore(FakePosixStateStore):
    def _chmod_path(self, path: Path, mode: int) -> None:
        raise OSError("chmod failed")


class BrokenProtector(FakeProtector):
    def unprotect(self, data: bytes) -> bytes:
        raise ValueError("invalid protected state")


def _install_fake_fs(monkeypatch):
    files: dict[str, bytes] = {}
    dirs: set[str] = set()

    def _key(path: Path) -> str:
        return str(path)

    def _mkdir(self, parents=False, exist_ok=False):
        dirs.add(_key(self))
        return None

    def _exists(self):
        key = _key(self)
        return key in files or key in dirs

    def _write_bytes(self, data: bytes):
        files[_key(self)] = data
        dirs.add(_key(self.parent))
        return len(data)

    def _read_bytes(self):
        return files[_key(self)]

    def _unlink(self, missing_ok=False):
        key = _key(self)
        if key not in files and not missing_ok:
            raise FileNotFoundError(key)
        files.pop(key, None)
        dirs.discard(key)
        return None

    monkeypatch.setattr(Path, "mkdir", _mkdir)
    monkeypatch.setattr(Path, "exists", _exists)
    monkeypatch.setattr(Path, "write_bytes", _write_bytes)
    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    monkeypatch.setattr(Path, "unlink", _unlink)


def test_windows_state_store_round_trips_with_protector(monkeypatch):
    _install_fake_fs(monkeypatch)
    store = GatewayStateStore(
        Path("virtual") / "gateway-state.dpapi",
        protector=FakeProtector(),
        platform_name="nt",
    )

    store.save({"gateway_credentials": {"gateway_id": "GW-1"}})

    assert store.load() == {"gateway_credentials": {"gateway_id": "GW-1"}}


def test_windows_state_store_recovers_from_decryption_failure(monkeypatch):
    _install_fake_fs(monkeypatch)
    store = GatewayStateStore(
        Path("virtual") / "gateway-state.dpapi",
        protector=BrokenProtector(),
        platform_name="nt",
    )
    store.path.write_bytes(b"invalid-state")

    assert store.load({"gateway_credentials": None}) == {"gateway_credentials": None}
    assert not store.path.exists()


def test_posix_state_store_enforces_owner_only_permissions(monkeypatch):
    _install_fake_fs(monkeypatch)
    store = FakePosixStateStore(Path("virtual") / "security" / "gateway-state.json")

    store.save({"gateway_credentials": {"gateway_id": "GW-1"}})

    assert store.load() == {"gateway_credentials": {"gateway_id": "GW-1"}}
    assert store._modes[store.path.parent] == 0o700
    assert store._modes[store.path] == 0o600


def test_posix_state_store_fails_when_permissions_cannot_be_hardened(monkeypatch):
    _install_fake_fs(monkeypatch)
    store = BrokenPosixStateStore(Path("virtual") / "security" / "gateway-state.json")

    with pytest.raises(RuntimeError, match="Unable to secure gateway state directory"):
        store.save({"gateway_credentials": {"gateway_id": "GW-1"}})
