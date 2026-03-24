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
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from scapy.all import sniff, IP
from colorama import Fore, Style
import logging

# Add parent directory to sys.path to allow importing modules from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.device_detector import DeviceDetector
from agent.flow_manager import FlowManager, FlowSummary
from agent.traffic_metadata import DomainHintCache, extract_flow_hints
try:
    from agent.dpi import WebInspectionController
except ImportError as e:
    logging.warning(f"DPI module failed to import: {e}. Running in degraded mode without DPI.")
    WebInspectionController = None

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "agent.json"
AGENT_RUNTIME_DIR = PROJECT_ROOT / "runtime" / "agent"

# =========================================================
# THREAD SAFE DEVICE INVENTORY (PERSISTENT)
# =========================================================

class DeviceInventory:
    def __init__(self, storage_file=None):
        self.lock = threading.Lock()
        AGENT_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        self.storage_file = Path(storage_file) if storage_file else AGENT_RUNTIME_DIR / "device_inventory.json"
        self.devices = {}
        self.load_inventory()
        threading.Thread(target=self._auto_save_worker, daemon=True).start()

    def load_inventory(self):
        if self.storage_file.exists():
            try:
                with self.storage_file.open("r", encoding="utf-8") as f:
                    self.devices = json.load(f)
                    print(f"{Fore.GREEN}[+] Loaded {len(self.devices)} devices from inventory.")
            except Exception:
                pass

    def _auto_save_worker(self):
        while True:
            time.sleep(30)
            self.save_inventory()

    def save_inventory(self):
        try:
            with self.lock:
                self.storage_file.parent.mkdir(parents=True, exist_ok=True)
                with self.storage_file.open("w", encoding="utf-8") as f:
                    json.dump(self.devices, f)
        except Exception:
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

    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self.config = self._load_config(config_path)
        self.hostname = socket.gethostname()
        self.agent_version = "v3.0-hybrid"

        url_config = self.config.get("server_url", "http://127.0.0.1:8000")
        base = url_config.rstrip("/")
        if "/api/v1/collect" in base:
            base = base.split("/api/v1/collect")[0]

        self.flow_url = base + "/api/v1/collect/flow/batch"
        self.heartbeat_url = base + "/api/v1/collect/heartbeat"
        self.devices_url = base + "/api/v1/collect/devices/batch"
        self.policy_url = base + "/api/v1/policy"
        self.web_policy_url = base + "/api/v1/collect/web-policy"
        self.web_events_url = base + "/api/v1/collect/web-events/batch"

        self.agent_id = self._init_agent_id()
        self.organization_id = self._resolve_initial_organization_id()
        self.api_key = os.getenv("AGENT_API_KEY") or self.config.get("api_key", "soc-agent-key-2026")
        self.heartbeat_interval = int(os.getenv("NETVISOR_AGENT_HEARTBEAT_SECONDS", "10"))
        self.web_proxy_port = int(os.getenv("NETVISOR_WEB_PROXY_PORT", "8899"))
        self.web_policy_refresh_seconds = int(os.getenv("NETVISOR_WEB_POLICY_REFRESH_SECONDS", "30"))
        self.headers = {"X-API-Key": self.api_key}
        self.local_ip = self._detect_local_ip()
        self.local_mac = self._detect_local_mac()

        self.is_running = True
        self.verbose = True
        
        self.device_inventory = DeviceInventory()
        self.device_detector = DeviceDetector(local_ip=self.local_ip)
        self.local_network = self.device_detector.infer_local_network(self.local_ip)
        if self.local_network:
            self.device_detector.set_network(self.local_network)
            logger.info("Discovery network set to %s", self.local_network)
        else:
            logger.warning("Unable to infer local network for ARP discovery; falling back to passive ARP cache only.")
        self.domain_cache = DomainHintCache()
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
        if WebInspectionController is not None:
            self.web_inspection = WebInspectionController(
                runtime_dir=AGENT_RUNTIME_DIR / "mitm",
                agent_id=self.agent_id,
                device_ip=self.local_ip,
                organization_id=self.organization_id,
                headers=self.headers,
                policy_url=self.web_policy_url,
                upload_url=self.web_events_url,
                proxy_port=self.web_proxy_port,
                policy_refresh_seconds=self.web_policy_refresh_seconds,
            )
            self.web_inspection.start()
            logger.info(
                "Web inspection launchers ready: %s",
                ", ".join(sorted((self.web_inspection.status_snapshot().get("launcher_paths") or {}).values())),
            )
        else:
            logger.warning("Web inspection is disabled because WebInspectionController could not be imported.")

    def _init_agent_id(self):
        AGENT_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        id_file = AGENT_RUNTIME_DIR / "agent_id.txt"
        if id_file.exists():
            with id_file.open("r", encoding="utf-8") as f:
                return f.read().strip()
        new_id = f"AGENT-{uuid.uuid4().hex[:8].upper()}"
        with id_file.open("w", encoding="utf-8") as f:
            f.write(new_id)
        return new_id

    def _load_config(self, path):
        try:
            config_path = Path(path)
            if config_path.exists():
                with config_path.open("r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _resolve_initial_organization_id(self):
        configured = (
            self.config.get("organization_id")
            or os.getenv("NETVISOR_ORGANIZATION_ID")
            or os.getenv("NETVISOR_DEFAULT_ORGANIZATION_ID")
        )
        return configured or "default-org-id"

    def _register_agent(self):
        retry_delay = 1
        while self.is_running:
            try:
                payload = {
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "os": platform.system(),
                    "version": self.agent_version,
                    "device_ip": self.local_ip,
                    "device_mac": self.local_mac,
                    "time": datetime.now().isoformat(),
                    "organization_id": self.organization_id
                }
                r = requests.post(self.heartbeat_url.replace("/heartbeat", "/register"), json=payload, headers=self.headers, timeout=5)
                r.raise_for_status()
                res = r.json()
                if res.get("organization_id"):
                    self.organization_id = res["organization_id"]
                    self.flow_manager.organization_id = self.organization_id
                    if hasattr(self, "web_inspection"):
                        self.web_inspection.update_context(organization_id=self.organization_id)
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
            if packet.haslayer(IP):
                hints = extract_flow_hints(packet, self.domain_cache)
                domain = hints.get("domain")
                sni = hints.get("sni")
                if domain:
                    packet.captured_domain = domain
                    if self.verbose:
                        print(f"{Fore.CYAN}[APP]{Style.RESET_ALL} {packet[IP].src} -> {domain}")
                if sni:
                    packet.captured_sni = sni

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
                    "hostname": self.hostname,
                    "os": platform.system(),
                    "version": self.agent_version,
                    "device_ip": self.local_ip,
                    "device_mac": self.local_mac,
                    "status": "online",
                    "dropped_packets": 0,
                    "cpu_usage": cpu,
                    "ram_usage": ram,
                    "inventory_size": len(self.device_inventory.devices),
                    "time": datetime.now().isoformat(),
                    "organization_id": self.organization_id,
                    "web_inspection": self.web_inspection.status_snapshot() if hasattr(self, "web_inspection") else {},
                }
                requests.post(self.heartbeat_url, json=payload, headers=self.headers, timeout=5)
            except Exception:
                pass
            time.sleep(self.heartbeat_interval)

    def _detect_local_ip(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("10.255.255.255", 1))
                return sock.getsockname()[0]
            finally:
                sock.close()
        except Exception:
            return "127.0.0.1"

    def _detect_local_mac(self):
        try:
            node = uuid.getnode()
            return ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -1, -8))
        except Exception:
            return "-"

    def _infer_os_family(self, hostname, device_type):
        hostname_value = str(hostname or "").lower()
        device_type_value = str(device_type or "").lower()

        if "windows" in device_type_value or hostname_value.startswith(("desktop-", "laptop-", "win-", "msi-", "asus-")):
            return "Windows"
        if "linux" in device_type_value or "unix" in device_type_value:
            return "Linux"
        if "printer" in device_type_value:
            return "Embedded"
        if "synology" in hostname_value or "nas" in hostname_value:
            return "Linux"
        return "Unknown"

    def _resolve_discovered_device(self, target):
        ip, mac = target
        existing = self.device_inventory.get(ip) or {}

        hostname = existing.get("hostname")
        if hostname in {None, "", "Unknown", "Unknown-Device"}:
            hostname = self.device_detector.resolve_hostname(ip) or "Unknown"

        device_type = existing.get("type")
        if device_type in {None, "", "Unknown", "Unknown Type"}:
            device_type = self.device_detector.detect_device_type(ip)
        if device_type == "Unknown Type":
            device_type = "Unknown"

        vendor = self._resolve_vendor(mac)
        os_family = existing.get("os")
        if os_family in {None, "", "Unknown"}:
            os_family = self._infer_os_family(hostname, device_type)

        confidence = "high" if hostname != "Unknown" else "medium"
        payload = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "os_family": os_family,
            "is_online": True,
            "organization_id": self.organization_id,
            "agent_id": self.agent_id,
        }
        return payload, confidence

    def _sync_discovered_devices(self, devices):
        if not devices:
            return

        try:
            if self.verbose:
                print(f"[*] Syncing {len(devices)} discovered devices...")
            response = requests.post(
                self.devices_url,
                json=devices,
                headers=self.headers,
                timeout=10,
            )
            if response.status_code != 200:
                print(f"{Fore.RED}[-] Device sync failed: {response.status_code} - {response.text}")
            response.raise_for_status()
        except Exception as exc:
            logger.warning("Discovered device sync failed: %s", exc)

    # --- DISCOVERY ENGINE ---
    def _discovery_engine(self):
        while self.is_running:
            try:
                arp_data = self.device_detector.collect_arp_candidates(self.local_network)
                candidates = []
                for ip, mac in arp_data.items():
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except Exception:
                        continue
                    if ip == self.local_ip:
                        continue
                    candidates.append((ip, mac))

                import concurrent.futures


                futures = {self.discovery_pool.submit(self._resolve_discovered_device, c): c for c in candidates}


                for future in concurrent.futures.as_completed(futures):


                    try:


                        payload, confidence = future.result()


                        self.device_inventory.update(
                        payload["ip"],
                        mac=payload["mac"],
                        hostname=payload["hostname"],
                        vendor=payload["vendor"],
                        type=payload["device_type"],
                        os=payload["os_family"],
                        confidence=confidence,
                    )


                        self._sync_discovered_devices([payload])


                    except Exception as exc:


                        logger.warning("Failed to resolve device: %s", exc)
            except Exception as exc:
                logger.warning("Discovery cycle failed: %s", exc)
            time.sleep(60)

    def _resolve_vendor(self, mac):
        if not mac or len(mac) < 8: return "Unknown"
        prefix = mac.upper().replace("-", ":")[:8]
        return self.vendor_cache.get(prefix, "Unknown")

    def stop(self):
        self.is_running = False
        if hasattr(self, "web_inspection"):
            self.web_inspection.stop()
        self.flow_manager.stop()
        self.device_inventory.save_inventory()
        sys.exit(0)

    def start(self, timeout=None):
        print(f"{Fore.BLUE}[*] Netvisor Hybrid Agent Starting...")
        sniff(prn=self.process_packet, store=False, promisc=True, timeout=timeout)

if __name__ == "__main__":
    agent = NetworkAgent(DEFAULT_CONFIG_PATH)
    try:
        agent.start(timeout=60)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down Netvisor Agent...{Style.RESET_ALL}")
    finally:
        agent.stop()
