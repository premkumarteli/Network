from __future__ import annotations

import os
import queue
import socket
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime

import requests
from colorama import Fore, Style
from scapy.all import IP, sniff

from agent.flow_manager import FlowManager, FlowSummary
from agent.traffic_metadata import DomainHintCache, extract_flow_hints

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GATEWAY_RUNTIME_DIR = PROJECT_ROOT / "runtime" / "gateway"


class GatewayCollector:
    def __init__(self) -> None:
        base_url = os.getenv("NETVISOR_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
        if "/api/v1" in base_url:
            base_url = base_url.split("/api/v1")[0]

        self.gateway_id = self._init_gateway_id()
        self.organization_id = (
            os.getenv("NETVISOR_ORGANIZATION_ID")
            or os.getenv("NETVISOR_DEFAULT_ORGANIZATION_ID")
            or "default-org-id"
        )
        self.gateway_flows_url = f"{base_url}/api/v1/gateway/flows/batch"
        self.register_url = f"{base_url}/api/v1/gateway/register"
        self.heartbeat_url = f"{base_url}/api/v1/gateway/heartbeat"
        self.capture_mode = os.getenv("NETVISOR_GATEWAY_CAPTURE_MODE", "promiscuous")
        self.heartbeat_interval = int(os.getenv("NETVISOR_GATEWAY_HEARTBEAT_SECONDS", "10"))
        self.headers = {"X-Gateway-Key": os.getenv("GATEWAY_API_KEY", os.getenv("AGENT_API_KEY", ""))}
        self.is_running = True
        self.upload_q: queue.Queue[dict] = queue.Queue(maxsize=10000)
        self.domain_cache = DomainHintCache()

        self.flow_manager = FlowManager(
            agent_id=self.gateway_id,
            organization_id=self.organization_id,
            on_flow_expired=self._on_flow_expired,
        )

        threading.Thread(target=self._upload_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()
        self._register_gateway()

    def _init_gateway_id(self) -> str:
        GATEWAY_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        id_file = GATEWAY_RUNTIME_DIR / "gateway_id.txt"
        if id_file.exists():
            with id_file.open("r", encoding="utf-8") as handle:
                return handle.read().strip()

        gateway_id = f"GATEWAY-{uuid.uuid4().hex[:8].upper()}"
        with id_file.open("w", encoding="utf-8") as handle:
            handle.write(gateway_id)
        return gateway_id

    def _register_gateway(self) -> None:
        payload = {
            "gateway_id": self.gateway_id,
            "hostname": socket.gethostname(),
            "capture_mode": self.capture_mode,
            "time": datetime.now().isoformat(),
        }
        try:
            requests.post(self.register_url, json=payload, headers=self.headers, timeout=5).raise_for_status()
            print(f"{Fore.GREEN}[+] Gateway registered: {self.gateway_id}")
        except Exception as exc:
            print(f"{Fore.YELLOW}[!] Gateway registration failed: {exc}")

    def _heartbeat_worker(self) -> None:
        while self.is_running:
            try:
                payload = {
                    "gateway_id": self.gateway_id,
                    "hostname": socket.gethostname(),
                    "capture_mode": self.capture_mode,
                    "time": datetime.now().isoformat(),
                }
                requests.post(self.heartbeat_url, json=payload, headers=self.headers, timeout=5)
            except Exception:
                pass
            time.sleep(self.heartbeat_interval)

    def _on_flow_expired(self, summary: FlowSummary) -> None:
        payload = dict(summary.__dict__)
        payload["source_type"] = "gateway"
        payload["metadata_only"] = True
        try:
            self.upload_q.put(payload, block=False)
        except queue.Full:
            print(f"{Fore.YELLOW}[!] Gateway upload queue full, dropping flow")

    def _upload_worker(self) -> None:
        batch: list[dict] = []
        last_send = time.time()

        while self.is_running:
            try:
                try:
                    record = self.upload_q.get(timeout=1.0)
                    batch.append(record)
                    self.upload_q.task_done()
                except queue.Empty:
                    pass

                if len(batch) >= 20 or (time.time() - last_send > 5 and batch):
                    try:
                        requests.post(self.gateway_flows_url, json=batch, headers=self.headers, timeout=10).raise_for_status()
                        batch = []
                        last_send = time.time()
                    except Exception as exc:
                        print(f"{Fore.YELLOW}[!] Gateway flow upload failed: {exc}")
                        time.sleep(2)
            except Exception:
                pass

    def process_packet(self, packet) -> None:
        if not packet.haslayer(IP):
            return

        hints = extract_flow_hints(packet, self.domain_cache)
        domain = hints.get("domain")
        sni = hints.get("sni")
        if domain:
            packet.captured_domain = domain
            print(f"{Fore.CYAN}[APP]{Style.RESET_ALL} {packet[IP].src} -> {domain}")
        if sni:
            packet.captured_sni = sni

        self.flow_manager.update_from_packet(packet)

    def start(self, timeout: int | None = None) -> None:
        print(f"{Fore.BLUE}[*] NetVisor Gateway Starting...")
        sniff(prn=self.process_packet, store=False, promisc=True, timeout=timeout)
