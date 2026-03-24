from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import requests

from .browser_launcher import BrowserLauncher
from .cert_manager import CertificateManager
from .event_buffer import EventBuffer
from .policy import InspectionPolicy
from .proxy_manager import ProxyManager

logger = logging.getLogger(__name__)


class WebInspectionController:
    def __init__(
        self,
        *,
        runtime_dir: Path,
        agent_id: str,
        device_ip: str,
        organization_id: str,
        headers: dict,
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
        self.headers = headers
        self.policy_url = policy_url
        self.upload_url = upload_url
        self.proxy_port = int(proxy_port)
        self.policy_refresh_seconds = int(policy_refresh_seconds)

        self.current_policy = InspectionPolicy.from_payload(None, agent_id=agent_id, device_ip=device_ip)
        self._status_lock = threading.Lock()
        self._status = {
            "inspection_enabled": False,
            "status": "disabled",
            "proxy_running": False,
            "ca_installed": False,
            "browser_support": list(self.current_policy.allowed_processes),
            "last_error": None,
            "launcher_paths": {},
        }
        self._running = False

        self.cert_manager = CertificateManager(self.runtime_dir)
        self.event_buffer = EventBuffer(
            upload_url=self.upload_url,
            headers=self.headers,
            get_policy=lambda: self.current_policy,
            get_context=self._context_snapshot,
        )
        self.proxy_manager = ProxyManager(
            runtime_dir=self.runtime_dir,
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
            response = requests.get(
                self.policy_url,
                params={
                    "agent_id": self.agent_id,
                    "device_ip": self.device_ip,
                    "organization_id": self.organization_id,
                },
                headers=self.headers,
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

    def _apply_policy(self) -> None:
        self.cert_manager.ensure_ca_files()
        cert_status = self.cert_manager.status()
        ca_installed = bool(cert_status.get("ca_installed"))
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

        self._set_status(
            inspection_enabled=self.current_policy.inspection_enabled,
            proxy_running=proxy_running,
            ca_installed=ca_installed,
            browser_support=list(self.current_policy.allowed_processes),
            last_error=last_error,
            status=status,
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
        snapshot["browser_support"] = list(snapshot.get("browser_support") or [])
        return snapshot
