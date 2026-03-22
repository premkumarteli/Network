from pathlib import Path

from agent.dpi.cert_manager import CertificateManager
from agent.dpi.controller import WebInspectionController
from agent.dpi.policy import InspectionPolicy


def test_certificate_manager_uses_recent_install_marker(monkeypatch, tmp_path):
    manager = CertificateManager(tmp_path)
    manager.ensure_ca_files()

    monkeypatch.setattr(manager, "_is_installed_via_powershell", lambda thumbprint: False)
    monkeypatch.setattr(manager, "_is_installed_via_certutil", lambda thumbprint: False)

    assert manager.is_installed() is False

    manager._mark_recent_install()

    assert manager.is_installed() is True


def test_web_inspection_controller_starts_proxy_even_when_ca_missing(monkeypatch, tmp_path):
    controller = WebInspectionController(
        runtime_dir=tmp_path,
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
        organization_id="default-org-id",
        headers={},
        policy_url="http://localhost/policy",
        upload_url="http://localhost/upload",
        proxy_port=8899,
        policy_refresh_seconds=30,
    )
    controller.current_policy = InspectionPolicy.from_payload(
        {"inspection_enabled": True},
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
    )

    monkeypatch.setattr(controller.cert_manager, "ensure_ca_files", lambda: None)
    monkeypatch.setattr(controller.cert_manager, "status", lambda: {"ca_installed": False})
    monkeypatch.setattr(
        controller.cert_manager,
        "install_if_needed",
        lambda: (False, "Timed out waiting for certificate approval"),
    )
    monkeypatch.setattr(
        controller.proxy_manager,
        "start",
        lambda **kwargs: (True, None),
    )

    controller._apply_policy()
    status = controller.status_snapshot()

    assert status["inspection_enabled"] is True
    assert status["proxy_running"] is True
    assert status["ca_installed"] is False
    assert status["status"] == "degraded"
    assert status["last_error"] == "Timed out waiting for certificate approval"
