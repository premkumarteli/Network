from pathlib import Path

from agent.dpi.cert_manager import CertificateManager
from agent.dpi.controller import WebInspectionController
from agent.dpi.policy import InspectionPolicy


class IdentityProtector:
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data


class FakeApiClient:
    def request(self, method, url, *, json_body=None, params=None, timeout=10):
        raise AssertionError("Network not expected in this unit test")


def test_certificate_manager_persists_dpapi_wrapped_key_and_sha256_thumbprint(monkeypatch, tmp_path):
    manager = CertificateManager(tmp_path, protector=IdentityProtector())
    manager.ensure_ca_files()

    monkeypatch.setattr(manager, "_is_currentuser_root_match", lambda thumbprint: False)

    status = manager.status()
    assert manager.key_path.name.endswith(".key.dpapi")
    assert status["thumbprint_sha256"]
    assert status["key_protection"] == "dpapi_user"
    assert status["trust_scope"] == "CurrentUserRoot"
    assert "days_until_expiry" in status
    assert "days_until_rotation_due" in status
    assert manager.is_installed() is False


def test_web_inspection_controller_starts_proxy_even_when_ca_missing(monkeypatch, tmp_path):
    controller = WebInspectionController(
        runtime_dir=tmp_path,
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
        organization_id="default-org-id",
        api_client=FakeApiClient(),
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
    assert status["privacy_guard_enabled"] is True
    assert status["sensitive_destination_bypass_enabled"] is True
