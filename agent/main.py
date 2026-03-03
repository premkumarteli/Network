import sys
import os
import threading
import time
import requests
import queue
import socket
import json
import uuid
import psutil
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from scapy.all import sniff, IP, DNS, DNSQR
from colorama import Fore, Style
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent directory to sys.path to allow importing modules from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.flow_manager import FlowManager, FlowSummary
from services.device_detector import DeviceDetector

# =========================================================
# THREAD SAFE DEVICE INVENTORY (PERSISTENT)
# =========================================================

class DeviceInventory:
    def __init__(self, storage_file="device_inventory.json"):
        self.lock = threading.Lock()
        self.storage_file = storage_file
        self.devices = {}
        self.load_inventory()
        threading.Thread(target=self._auto_save_worker, daemon=True).start()

    def load_inventory(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    self.devices = json.load(f)
                    print(f"{Fore.GREEN}[+] Loaded {len(self.devices)} devices from inventory.")
            except:
                pass

    def _auto_save_worker(self):
        while True:
            time.sleep(30)
            self.save_inventory()

    def save_inventory(self):
        try:
            with self.lock:
                with open(self.storage_file, "w") as f:
                    json.dump(self.devices, f)
        except:
            pass

    def update(self, ip, **kwargs):
        with self.lock:
            if ip not in self.devices:
                self.devices[ip] = {
                    "mac": "-",
                    "hostname": "Unknown",
                    "vendor": "Unknown",
                    "os": "Unknown",
                    "type": "Unknown",
                    "confidence": "low",
                    "last_seen": time.time()
                }

            for k, v in kwargs.items():
                if v and v not in ["Unknown", "-"]:
                    self.devices[ip][k] = v

            self.devices[ip]["last_seen"] = time.time()

    def get(self, ip):
        return self.devices.get(ip)


# =========================================================
# MAIN AGENT
# =========================================================

class NetworkAgent:

    def __init__(self, config_path="core/config.json"):
        self.config = self._load_config(config_path)

        url_config = self.config.get("server_url", "http://127.0.0.1:8000")
        base = url_config.rstrip("/")
        if "/api/v1/collect" in base:
            base = base.split("/api/v1/collect")[0]

        self.flow_url = base + "/api/v1/collect/flow/batch"
        self.heartbeat_url = base + "/api/v1/collect/heartbeat"
        self.policy_url = base + "/api/v1/policy"

        self.agent_id = self._init_agent_id()
        self.organization_id = self.config.get("organization_id", "default-org-id")
        self.api_key = os.getenv("AGENT_API_KEY") or self.config.get("api_key", "soc-agent-key-2026")
        self.headers = {"X-API-Key": self.api_key}

        self.is_running = True
        self.verbose = True
        
        self.device_inventory = DeviceInventory()
        self.device_detector = DeviceDetector()
        self.probing_ips = set()
        
        # OUI Vendor Cache
        self.vendor_cache = {
            "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", 
            "00:1C:14": "VMware", "08:00:27": "Oracle VirtualBox", 
            "00:15:5D": "Microsoft Hyper-V", "DC:A6": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi", "D8:3A:DD": "Ubiquiti", 
            "F0:9F:C2": "Ubiquiti", "00:11:32": "Synology"
        }

        # --- FLOW MANAGER (PHASE 1) ---
        self.flow_manager = FlowManager(
            agent_id=self.agent_id,
            organization_id=self.organization_id,
            on_flow_expired=self._on_flow_expired
        )

        # Queues and Thread Pools
        self.upload_q = queue.Queue(maxsize=10000)
        self.discovery_pool = ThreadPoolExecutor(max_workers=5)

        # Start Workers
        print("[*] Starting upload worker...")
        threading.Thread(target=self._upload_worker, daemon=True).start()
        print("[*] Starting heartbeat worker...")
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()
        print("[*] Starting discovery engine...")
        threading.Thread(target=self._discovery_engine, daemon=True).start()
        
        self._register_agent()

    def _init_agent_id(self):
        id_file = "agent_id.txt"
        if os.path.exists(id_file):
            with open(id_file, "r") as f:
                return f.read().strip()
        new_id = f"AGENT-{uuid.uuid4().hex[:8].upper()}"
        with open(id_file, "w") as f:
            f.write(new_id)
        return new_id

    def _load_config(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _register_agent(self):
        retry_delay = 1
        while self.is_running:
            try:
                payload = {
                    "agent_id": self.agent_id,
                    "hostname": socket.gethostname(),
                    "os": platform.system(),
                    "version": "v3.0-hybrid",
                    "time": datetime.now().isoformat(),
                    "organization_id": self.organization_id
                }
                r = requests.post(self.heartbeat_url.replace("/heartbeat", "/register"), json=payload, headers=self.headers, timeout=5)
                r.raise_for_status()
                res = r.json()
                if res.get("organization_id"):
                    self.organization_id = res["organization_id"]
                print(f"{Fore.GREEN}[+] Hybrid Flow Agent Registered: {self.agent_id}")
                return
            except Exception as e:
                logger.warning(f"Registration failed: {e}. Retrying...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)

    def _on_flow_expired(self, summary: FlowSummary):
        """Callback from FlowManager when a flow is ready for upload."""
        try:
            # Add DNS metadata if applicable (simplified for now)
            # In a full impl, we'd correlate DNS queries with flows here
            self.upload_q.put(summary.__dict__, block=False)
        except queue.Full:
            logger.warning("Upload queue full - dropping flow summary")

    def process_packet(self, packet):
        """Phase 1: Direct packet to FlowManager for feature extraction."""
        try:
            # Capture domain for flow correlation
            if packet.haslayer(IP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
                domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
                packet.captured_domain = domain
                if self.verbose:
                    print(f"{Fore.CYAN}[DNS]{Style.RESET_ALL} {packet[IP].src} -> {domain}")

            self.flow_manager.update_from_packet(packet)
        except Exception as e:
            print(f"ERROR in process_packet: {e}")
            logger.error(f"Packet error: {e}")

    def _upload_worker(self):
        batch = []
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
                        r = requests.post(self.flow_url, json=batch, headers=self.headers, timeout=10.0)
                        r.raise_for_status()
                        batch = []
                        last_send = time.time()
                    except Exception as e:
                        logger.error(f"Flow upload failed: {e}")
                        time.sleep(2) # Backoff
            except Exception as e:
                logger.error(f"Upload worker error: {e}")

    def _heartbeat_worker(self):
        while self.is_running:
            try:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent
                payload = {
                    "agent_id": self.agent_id,
                    "status": "online",
                    "dropped_packets": 0,
                    "cpu_usage": cpu,
                    "ram_usage": ram,
                    "inventory_size": len(self.device_inventory.devices),
                    "time": datetime.now().isoformat(),
                    "organization_id": self.organization_id
                }
                requests.post(self.heartbeat_url, json=payload, headers=self.headers, timeout=5)
            except: pass
            time.sleep(30)

    # --- DISCOVERY ENGINE ---
    def _discovery_engine(self):
        while self.is_running:
            try:
                arp_data = self.device_detector.parse_arp_table()
                for ip, mac in arp_data.items():
                    # Filter for internal IPs only
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except:
                        continue
                        
                    vendor = self._resolve_vendor(mac)
                    self.device_inventory.update(ip, mac=mac, vendor=vendor)
            except: pass
            time.sleep(60)

    def _resolve_vendor(self, mac):
        if not mac or len(mac) < 8: return "Unknown"
        prefix = mac.upper().replace("-", ":")[:8]
        return self.vendor_cache.get(prefix, "Unknown")

    def stop(self):
        self.is_running = False
        self.flow_manager.stop()
        self.device_inventory.save_inventory()
        sys.exit(0)

    def start(self, timeout=None):
        print(f"{Fore.BLUE}[*] Netvisor Hybrid Agent Starting...")
        sniff(prn=self.process_packet, store=False, promisc=True, timeout=timeout)

if __name__ == "__main__":
    NetworkAgent("core/config.json").start(timeout=60)
