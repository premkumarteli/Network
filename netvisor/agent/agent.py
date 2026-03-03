import socket
import platform
import uuid
import threading
import time
from scapy.all import sniff, DNSQR
from .collector import FlowManager
from .communication.api_client import APIClient

class NetVisorAgent:
    def __init__(self, server_url, api_key, organization_id="default"):
        self.server_url = server_url
        self.api_key = api_key
        self.organization_id = organization_id
        self.agent_id = self._get_id()
        self.client = APIClient(server_url, api_key)
        self.flow_manager = FlowManager(self.agent_id, self.organization_id, self._on_flow_expired)
        self.upload_queue = []
        self._lock = threading.Lock()
        
        self.register()
        threading.Thread(target=self._upload_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()

    def _get_id(self):
        return f"AGENT-{uuid.getnode()}" # Simplified for now

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
            print(f"[+] Agent Registered: {self.agent_id}")
        except Exception as e:
            print(f"[-] Registration failed: {e}")

    def _on_flow_expired(self, summary):
        with self._lock:
            self.upload_queue.append(summary)

    def _upload_worker(self):
        while True:
            time.sleep(10)
            with self._lock:
                if not self.upload_queue: continue
                batch = self.upload_queue[:]
                self.upload_queue = []
            try:
                self.client.upload_flows(batch)
            except:
                with self._lock:
                    self.upload_queue = batch + self.upload_queue

    def _heartbeat_worker(self):
        while True:
            try:
                self.client.heartbeat({"agent_id": self.agent_id})
            except: pass
            time.sleep(30)

    def process_packet(self, packet):
        if packet.haslayer(DNSQR):
            packet.captured_domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
        self.flow_manager.update_from_packet(packet)

    def start(self):
        print(f"[*] NetVisor Agent {self.agent_id} starting capture...")
        sniff(prn=self.process_packet, store=False)

if __name__ == "__main__":
    agent = NetVisorAgent("http://localhost:8000/api/v1", "soc-agent-key-2026")
    agent.start()
