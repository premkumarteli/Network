import socket
import platform
import uuid
import threading
import time
import logging
from scapy.all import sniff, DNSQR
from .collector import FlowManager
from .communication.api_client import APIClient
from .discovery import NetworkScanner, PeriodicScanner

logger = logging.getLogger("netvisor.agent")


class NetVisorAgent:
    def __init__(self, server_url, api_key, organization_id="default", scan_interval=120):
        self.server_url = server_url
        self.api_key = api_key
        self.organization_id = organization_id
        self.agent_id = self._get_id()
        self.client = APIClient(server_url, api_key)
        self.flow_manager = FlowManager(self.agent_id, self.organization_id, self._on_flow_expired)
        self.upload_queue = []
        self._lock = threading.Lock()

        # Register with backend
        self.register()

        # Start background workers
        threading.Thread(target=self._upload_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()

        # Start device discovery scanner
        self._start_device_scanner(scan_interval)

    def _get_id(self):
        return f"AGENT-{uuid.getnode()}"

    def register(self):
        try:
            res = self.client.register({
                "agent_id": self.agent_id,
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "organization_id": self.organization_id
            })
            if res.get("organization_id"):
                self.organization_id = res["organization_id"]
            logger.info(f"Agent Registered: {self.agent_id}")
        except Exception as e:
            logger.error(f"Registration failed: {e}")

    def _start_device_scanner(self, interval):
        """Initialize and start the periodic ARP device scanner."""
        try:
            scanner = NetworkScanner()
            self._periodic_scanner = PeriodicScanner(
                scanner=scanner,
                interval=interval,
                on_scan_complete=self._on_devices_discovered,
            )
            self._periodic_scanner.start()
            logger.info(f"Device scanner started (interval={interval}s)")
        except RuntimeError as e:
            logger.error(f"Could not start device scanner: {e}")
            self._periodic_scanner = None

    def _on_devices_discovered(self, devices):
        """Callback from PeriodicScanner — upload discovered devices to backend."""
        # Tag each device with agent/org metadata
        for dev in devices:
            dev["agent_id"] = self.agent_id
            dev["organization_id"] = self.organization_id

        try:
            self.client.upload_devices(devices)
            logger.info(f"Uploaded {len(devices)} discovered device(s) to backend.")
        except Exception as e:
            logger.error(f"Failed to upload devices: {e}")

    def _on_flow_expired(self, summary):
        with self._lock:
            self.upload_queue.append(summary)

    def _upload_worker(self):
        while True:
            time.sleep(10)
            with self._lock:
                if not self.upload_queue:
                    continue
                batch = self.upload_queue[:]
                self.upload_queue = []
            try:
                self.client.upload_flows(batch)
            except Exception as e:
                with self._lock:
                    self.upload_queue = batch + self.upload_queue

    def _heartbeat_worker(self):
        while True:
            try:
                self.client.heartbeat({"agent_id": self.agent_id})
            except Exception:
                pass
            time.sleep(30)

    def process_packet(self, packet):
        if packet.haslayer(DNSQR):
            packet.captured_domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
        self.flow_manager.update_from_packet(packet)

    def start(self):
        logger.info(f"NetVisor Agent {self.agent_id} starting capture...")
        print(f"[*] NetVisor Agent {self.agent_id} starting capture...")
        sniff(prn=self.process_packet, store=False)

if __name__ == "__main__":
    import os
    logging.basicConfig(level=logging.INFO)
    api_key = os.getenv("AGENT_API_KEY", "soc-agent-key-2026")
    agent = NetVisorAgent("http://localhost:8000/api/v1", api_key)
    agent.start()
