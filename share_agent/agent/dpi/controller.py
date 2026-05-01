from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from .browser_launcher import BrowserLauncher
from .cert_manager import CertificateManager
from .event_buffer import EventBuffer
from .policy import InspectionPolicy
from .proxy_manager import ProxyManager
from ..security import AgentApiClient

logger = logging.getLogger(__name__)


class WebInspectionController:
    def __init__(
        self,
        *,
        runtime_dir: Path,
        agent_id: str,
        device_ip: str,
        organization_id: str,
        api_client: AgentApiClient,
        policy_url: str,
        upload_url: str,
        proxy_port: int = 8899,
        policy_refresh_seconds: int = 30,
    ) -> None:
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.agent_id = agent_id
        self.device_ip = device_ip
        self.organization_id = organization_id
        self.api_client = api_client
        self.policy_url = policy_url
        self.upload_url = upload_url
        self.proxy_port = int(proxy_port)
        self.policy_refresh_seconds = int(policy_refresh_seconds)

        self.current_policy = InspectionPolicy.from_payload(None, agent_id=agent_id, device_ip=device_ip)
        self._status_lock = threading.Lock()
        self._status = {
            "inspection_enabled": False,
            "privacy_guard_enabled": bool(self.current_policy.privacy_guard_enabled),
            "sensitive_destination_bypass_enabled": bool(self.current_policy.sensitive_destination_bypass_enabled),
            "status": "disabled",
            "proxy_running": False,
            "ca_installed": False,
            "ca_status": "missing",
            "thumbprint_sha256": None,
            "issued_at": None,
            "expires_at": None,
            "rotation_due_at": None,
            "days_until_expiry": None,
            "days_until_rotation_due": None,
            "expires_soon": None,
            "rotation_due_soon": None,
            "trust_store_match": False,
            "trust_scope": "CurrentUserRoot",
            "key_protection": "dpapi_user",
            "proxy_pid": None,
            "proxy_port": self.proxy_port,
            "browser_support": list(self.current_policy.allowed_processes),
            "last_error": None,
            "last_event_at": None,
            "last_upload_at": None,
            "queue_size": 0,
            "spooled_event_count": 0,
            "dropped_event_count": 0,
            "uploaded_event_count": 0,
            "upload_failures": 0,
            "last_drop_reason": None,
            "drop_reasons": {},
            "launcher_paths": {},
        }
        self._running = False

        self.cert_manager = CertificateManager(self.runtime_dir)
        self.event_buffer = EventBuffer(
            runtime_dir=self.runtime_dir,
            upload_url=self.upload_url,
            api_client=self.api_client,
            get_policy=lambda: self.current_policy,
            get_context=self._context_snapshot,
        )
        self.proxy_manager = ProxyManager(
            runtime_dir=self.runtime_dir,
            cert_manager=self.cert_manager,
            addon_path=Path(__file__).with_name("mitm_addon.py").resolve(),
            port=self.proxy_port,
            on_event=self.event_buffer.enqueue,
        )
        self.browser_launcher = BrowserLauncher(self.runtime_dir, self.proxy_port)
        self._policy_thread = threading.Thread(target=self._policy_worker, daemon=True)

    def _context_snapshot(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "device_ip": self.device_ip,
            "organization_id": self.organization_id,
        }

    def update_context(self, *, device_ip: str | None = None, organization_id: str | None = None) -> None:
        if device_ip:
            self.device_ip = device_ip
            self.current_policy.device_ip = device_ip
        if organization_id:
            self.organization_id = organization_id

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._status["launcher_paths"] = self.browser_launcher.create_wrappers()
        logger.info("[DPI] Web inspection launchers created in: %s", self.runtime_dir)
        for name, path in self._status["launcher_paths"].items():
             logger.info("[DPI]   -> %s: %s", name, path)
        self.event_buffer.start()
        self.refresh_policy()
        self._policy_thread.start()

    def stop(self) -> None:
        self._running = False
        self.proxy_manager.stop()
        self.event_buffer.stop()

    def refresh_policy(self) -> None:
        try:
            response = self.api_client.request(
                "GET",
                self.policy_url,
                params={
                    "agent_id": self.agent_id,
                    "device_ip": self.device_ip,
                    "organization_id": self.organization_id,
                },
                timeout=10,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            self._set_status(last_error=f"Policy refresh failed: {exc}")
            return

        self.current_policy = InspectionPolicy.from_payload(
            payload,
            agent_id=self.agent_id,
            device_ip=self.device_ip,
        )
        self._apply_policy()

    def _live_metrics(self) -> dict:
        proxy_status = self.proxy_manager.status()
        buffer_metrics = self.event_buffer.metrics_snapshot()
        cert_status = self.cert_manager.status()
        return {
            "privacy_guard_enabled": bool(self.current_policy.privacy_guard_enabled),
            "sensitive_destination_bypass_enabled": bool(self.current_policy.sensitive_destination_bypass_enabled),
            "proxy_running": proxy_status.get("proxy_running", False),
            "proxy_pid": proxy_status.get("proxy_pid"),
            "proxy_port": proxy_status.get("proxy_port", self.proxy_port),
            "proxy_last_event_at": proxy_status.get("last_event_at"),
            "captured_event_count": proxy_status.get("captured_event_count", 0),
            "last_error": proxy_status.get("last_error"),
            "ca_installed": cert_status.get("ca_installed", False),
            "ca_status": cert_status.get("ca_status", "missing"),
            "thumbprint_sha256": cert_status.get("thumbprint_sha256"),
            "issued_at": cert_status.get("issued_at"),
            "expires_at": cert_status.get("expires_at"),
            "rotation_due_at": cert_status.get("rotation_due_at"),
            "days_until_expiry": cert_status.get("days_until_expiry"),
            "days_until_rotation_due": cert_status.get("days_until_rotation_due"),
            "expires_soon": cert_status.get("expires_soon"),
            "rotation_due_soon": cert_status.get("rotation_due_soon"),
            "trust_store_match": cert_status.get("trust_store_match", False),
            "trust_scope": cert_status.get("trust_scope"),
            "key_protection": cert_status.get("key_protection"),
            "last_event_at": buffer_metrics.get("last_event_at") or proxy_status.get("last_event_at"),
            "last_upload_at": buffer_metrics.get("last_upload_at"),
            "queue_size": buffer_metrics.get("queue_size", 0),
            "spooled_event_count": buffer_metrics.get("spooled_event_count", 0),
            "dropped_event_count": buffer_metrics.get("dropped_event_count", 0),
            "uploaded_event_count": buffer_metrics.get("uploaded_event_count", 0),
            "upload_failures": buffer_metrics.get("upload_failures", 0),
            "last_drop_reason": buffer_metrics.get("last_drop_reason"),
            "drop_reasons": buffer_metrics.get("drop_reasons", {}),
        }

    def _apply_policy(self) -> None:
        self.cert_manager.ensure_ca_files()
        cert_status = self.cert_manager.status()
        ca_installed = bool(cert_status.get("ca_installed"))
        ca_status = cert_status.get("ca_status") or ("installed" if ca_installed else "missing")
        last_error = None
        proxy_running = False
        status = "disabled"

        if self.current_policy.inspection_enabled:
            if not ca_installed:
                ca_installed, install_error = self.cert_manager.install_if_needed()
                if install_error:
                    last_error = install_error

            proxy_running, proxy_error = self.proxy_manager.start(
                allowed_domains=self.current_policy.allowed_domains,
                snippet_max_bytes=self.current_policy.snippet_max_bytes,
            )
            if proxy_error:
                last_error = proxy_error

            if proxy_running and ca_installed:
                status = "running"
            elif proxy_running:
                status = "degraded"
            else:
                status = "degraded"
        else:
            self.proxy_manager.stop()

        live_metrics = self._live_metrics()
        self._set_status(
            inspection_enabled=self.current_policy.inspection_enabled,
            privacy_guard_enabled=self.current_policy.privacy_guard_enabled,
            sensitive_destination_bypass_enabled=self.current_policy.sensitive_destination_bypass_enabled,
            proxy_running=proxy_running,
            ca_installed=ca_installed,
            ca_status=ca_status,
            thumbprint_sha256=live_metrics.get("thumbprint_sha256"),
            issued_at=live_metrics.get("issued_at"),
            expires_at=live_metrics.get("expires_at"),
            rotation_due_at=live_metrics.get("rotation_due_at"),
            days_until_expiry=live_metrics.get("days_until_expiry"),
            days_until_rotation_due=live_metrics.get("days_until_rotation_due"),
            expires_soon=live_metrics.get("expires_soon"),
            rotation_due_soon=live_metrics.get("rotation_due_soon"),
            trust_store_match=live_metrics.get("trust_store_match"),
            trust_scope=live_metrics.get("trust_scope"),
            key_protection=live_metrics.get("key_protection"),
            browser_support=list(self.current_policy.allowed_processes),
            last_error=last_error or live_metrics.get("last_error"),
            status=status,
            proxy_pid=live_metrics.get("proxy_pid"),
            proxy_port=live_metrics.get("proxy_port"),
            last_event_at=live_metrics.get("last_event_at"),
            last_upload_at=live_metrics.get("last_upload_at"),
            queue_size=live_metrics.get("queue_size"),
            spooled_event_count=live_metrics.get("spooled_event_count"),
            dropped_event_count=live_metrics.get("dropped_event_count"),
            uploaded_event_count=live_metrics.get("uploaded_event_count"),
            upload_failures=live_metrics.get("upload_failures"),
            last_drop_reason=live_metrics.get("last_drop_reason"),
            drop_reasons=live_metrics.get("drop_reasons"),
        )

    def _set_status(self, **updates) -> None:
        with self._status_lock:
            self._status.update({k: v for k, v in updates.items() if v is not None or k == "last_error"})

    def _policy_worker(self) -> None:
        while self._running:
            try:
                self.refresh_policy()
            except Exception as exc:
                logger.debug("Web inspection policy worker error: %s", exc)
            time.sleep(self.policy_refresh_seconds)

    def status_snapshot(self) -> dict:
        with self._status_lock:
            snapshot = dict(self._status)
        live_metrics = self._live_metrics()
        snapshot.update(
            {
                "proxy_running": bool(snapshot.get("proxy_running") or live_metrics.get("proxy_running")),
                "proxy_pid": live_metrics.get("proxy_pid"),
                "proxy_port": live_metrics.get("proxy_port"),
                "ca_installed": bool(snapshot.get("ca_installed") or live_metrics.get("ca_installed")),
                "ca_status": live_metrics.get("ca_status", snapshot.get("ca_status")),
                "privacy_guard_enabled": live_metrics.get("privacy_guard_enabled"),
                "sensitive_destination_bypass_enabled": live_metrics.get("sensitive_destination_bypass_enabled"),
                "thumbprint_sha256": live_metrics.get("thumbprint_sha256"),
                "issued_at": live_metrics.get("issued_at"),
                "expires_at": live_metrics.get("expires_at"),
                "rotation_due_at": live_metrics.get("rotation_due_at"),
                "days_until_expiry": live_metrics.get("days_until_expiry"),
                "days_until_rotation_due": live_metrics.get("days_until_rotation_due"),
                "expires_soon": live_metrics.get("expires_soon"),
                "rotation_due_soon": live_metrics.get("rotation_due_soon"),
                "trust_store_match": live_metrics.get("trust_store_match"),
                "trust_scope": live_metrics.get("trust_scope"),
                "key_protection": live_metrics.get("key_protection"),
                "last_event_at": live_metrics.get("last_event_at"),
                "last_upload_at": live_metrics.get("last_upload_at"),
                "queue_size": live_metrics.get("queue_size"),
                "spooled_event_count": live_metrics.get("spooled_event_count"),
                "dropped_event_count": live_metrics.get("dropped_event_count"),
                "uploaded_event_count": live_metrics.get("uploaded_event_count"),
                "upload_failures": live_metrics.get("upload_failures"),
                "last_drop_reason": live_metrics.get("last_drop_reason"),
                "drop_reasons": live_metrics.get("drop_reasons"),
            }
        )
        snapshot["browser_support"] = list(snapshot.get("browser_support") or [])
        snapshot["metrics"] = {
            "proxy_pid": snapshot.get("proxy_pid"),
            "proxy_port": snapshot.get("proxy_port"),
            "ca_status": snapshot.get("ca_status"),
            "thumbprint_sha256": snapshot.get("thumbprint_sha256"),
            "issued_at": snapshot.get("issued_at"),
            "expires_at": snapshot.get("expires_at"),
            "rotation_due_at": snapshot.get("rotation_due_at"),
            "days_until_expiry": snapshot.get("days_until_expiry"),
            "days_until_rotation_due": snapshot.get("days_until_rotation_due"),
            "expires_soon": snapshot.get("expires_soon"),
            "rotation_due_soon": snapshot.get("rotation_due_soon"),
            "trust_store_match": snapshot.get("trust_store_match"),
            "trust_scope": snapshot.get("trust_scope"),
            "key_protection": snapshot.get("key_protection"),
            "last_event_at": snapshot.get("last_event_at"),
            "last_upload_at": snapshot.get("last_upload_at"),
            "queue_size": snapshot.get("queue_size"),
            "spooled_event_count": snapshot.get("spooled_event_count"),
            "dropped_event_count": snapshot.get("dropped_event_count"),
            "uploaded_event_count": snapshot.get("uploaded_event_count"),
            "upload_failures": snapshot.get("upload_failures"),
            "last_drop_reason": snapshot.get("last_drop_reason"),
            "drop_reasons": snapshot.get("drop_reasons") or {},
            "privacy_guard_enabled": snapshot.get("privacy_guard_enabled"),
            "sensitive_destination_bypass_enabled": snapshot.get("sensitive_destination_bypass_enabled"),
        }
        return snapshot
