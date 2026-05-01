from __future__ import annotations

from pathlib import Path

from agent.dpi.proxy_manager import ProxyManager


class _FakeProcess:
    def __init__(self):
        self.stdout = None
        self.stderr = None
        self.pid = 4321

    def poll(self):
        return None

    def terminate(self):
        return None

    def wait(self, timeout=None):
        return None

    def kill(self):
        return None


class _FakeCertManager:
    def cleanup_runtime_bundle(self, target_dir):
        return None

    def prepare_runtime_bundle(self, target_dir):
        return None


def test_proxy_manager_start_does_not_use_ssl_insecure(monkeypatch, tmp_path):
    runtime_dir = Path(tmp_path)
    manager = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=_FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda event: None,
    )

    monkeypatch.setattr(manager, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(manager, "_prepare_mitm_certs", lambda: None)
    captured = {}

    def _fake_popen(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        return _FakeProcess()

    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", _fake_popen)

    success, error = manager.start(allowed_domains=["example.com"], snippet_max_bytes=256)

    assert success is True
    assert error is None
    assert "--ssl-insecure" not in captured["cmd"]
    assert captured["cmd"][0] == "mitmdump"
