import argparse
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
from colorama import Fore, Style
import logging

# Add parent directory to sys.path to allow importing modules from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.device_detector import DeviceDetector
from agent.security import AgentApiClient
from shared.collector import (
    DomainHintCache,
    FlowManager,
    FlowSummary,
    PacketObservation,
    build_capture_backend,
)
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

    def __init__(self, config_path=DEFAULT_CONFIG_PATH, *, start_background_workers: bool = True):
        self.config = self._load_config(config_path)
        self.hostname = socket.gethostname()
        self.agent_version = "v3.0-hybrid"
        self._background_workers_enabled = bool(start_background_workers)

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
        self.capture_interface = (
            os.getenv("NETVISOR_AGENT_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        self.capture_backend_name = (
            os.getenv("NETVISOR_AGENT_CAPTURE_BACKEND")
            or os.getenv("NETVISOR_CAPTURE_BACKEND")
            or "auto"
        ).strip() or "auto"
        self.api_client = AgentApiClient(
            state_path=AGENT_RUNTIME_DIR / "security" / "agent_transport_state.dpapi",
            bootstrap_api_key=self.api_key,
            initial_pins=self._load_initial_backend_pins(),
        )
        self.local_ip = self._detect_local_ip()
        self.local_mac = self._detect_local_mac()

        self.is_running = True
        self.verbose = str(os.getenv("NETVISOR_PACKET_TRACE", "false")).strip().lower() in {"1", "true", "yes", "on"}
        
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
            on_flow_expired=self._on_flow_expired,
            source_type="agent",
            metadata_only=False,
            flush_interval=float(os.getenv("NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS", "5")),
            cleanup_interval=float(os.getenv("NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS", "5")),
            max_flows=int(os.getenv("NETVISOR_FLOW_MAX_ACTIVE_FLOWS", "50000")),
            start_worker=self._background_workers_enabled,
        )
        self.capture_backend = build_capture_backend(
            role="agent",
            interface=self.capture_interface,
            requested_backend=self.capture_backend_name,
        )

        # Queues and Thread Pools
        self.upload_q = queue.Queue(maxsize=10000)
        self.discovery_pool = ThreadPoolExecutor(max_workers=5)

        if self._background_workers_enabled:
            self._register_agent(force_reenroll=not self.api_client.has_credentials())

            # Start Workers only after registration so the backend can return the
            # canonical organization id before discovery/heartbeat traffic begins.
            print("[*] Starting upload worker...")
            threading.Thread(target=self._upload_worker, daemon=True).start()
            print("[*] Starting heartbeat worker...")
            threading.Thread(target=self._heartbeat_worker, daemon=True).start()
            print("[*] Starting discovery engine...")
            threading.Thread(target=self._discovery_engine, daemon=True).start()

            if WebInspectionController is not None:
                self.web_inspection = WebInspectionController(
                    runtime_dir=AGENT_RUNTIME_DIR / "mitm",
                    agent_id=self.agent_id,
                    device_ip=self.local_ip,
                    organization_id=self.organization_id,
                    api_client=self.api_client,
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
        else:
            logger.info("Agent background workers disabled for probe mode.")

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

    def _load_initial_backend_pins(self):
        configured = self.config.get("backend_tls_pins")
        if isinstance(configured, list):
            return configured
        raw = os.getenv("NETVISOR_BACKEND_TLS_PINS_JSON", "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except ValueError:
            logger.warning("Invalid NETVISOR_BACKEND_TLS_PINS_JSON value; starting without seed pins.")
            return []
        return parsed if isinstance(parsed, list) else []

    def status_snapshot(self):
        web_inspection = self.web_inspection.status_snapshot() if hasattr(self, "web_inspection") else {}
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "version": self.agent_version,
            "organization_id": self.organization_id,
            "local_ip": self.local_ip,
            "local_mac": self.local_mac,
            "background_workers_enabled": self._background_workers_enabled,
            "running": self.is_running,
            "upload_queue_depth": self.upload_q.qsize(),
            "device_inventory_size": len(self.device_inventory.devices),
            "flow_manager": self.flow_manager.status_snapshot(),
            "capture": self.capture_backend.status_snapshot(),
            "transport": self.api_client.status_snapshot(),
            "web_inspection": web_inspection,
        }

    def _register_agent(self, *, force_reenroll: bool = False):
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
                    "organization_id": self.organization_id,
                    "reenroll": bool(force_reenroll),
                }
                r = self.api_client.bootstrap_post(
                    self.heartbeat_url.replace("/heartbeat", "/register"),
                    json_body=payload,
                    timeout=5,
                    reenroll=force_reenroll,
                )
                r.raise_for_status()
                res = r.json()
                if res.get("organization_id"):
                    self.organization_id = res["organization_id"]
                    self.flow_manager.organization_id = self.organization_id
                    if hasattr(self, "web_inspection"):
                        self.web_inspection.update_context(organization_id=self.organization_id)
                has_credentials = self.api_client.has_credentials()
                if not has_credentials:
                    raise RuntimeError(
                        "Agent registration did not yield signed credentials and no stored credential is available. "
                        "This agent requires explicit credential rotation or re-enrollment before it can continue."
                    )
                if force_reenroll:
                    print(f"{Fore.GREEN}[+] Agent re-enrolled: {self.agent_id}")
                else:
                    print(f"{Fore.GREEN}[+] Hybrid Flow Agent Registered: {self.agent_id}")
                return
            except RuntimeError:
                raise
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

    def process_packet(self, packet) -> bool:
        """Phase 1: Direct packet to FlowManager for feature extraction."""
        try:
            observation = PacketObservation.from_packet(
                packet,
                source_type="agent",
                metadata_only=False,
                domain_cache=self.domain_cache,
            )
            if observation is None:
                return False

            if observation.domain and self.verbose:
                print(f"{Fore.CYAN}[APP]{Style.RESET_ALL} {observation.src_ip} -> {observation.domain}")

            self.flow_manager.update_from_observation(observation)
            return True
        except Exception as e:
            print(f"ERROR in process_packet: {e}")
            logger.error(f"Packet error: {e}")
            return False

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
                        r = self.api_client.request("POST", self.flow_url, json_body=batch, timeout=10.0)
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
                if not self.api_client.has_credentials():
                    self._register_agent(force_reenroll=True)
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
                response = self.api_client.request("POST", self.heartbeat_url, json_body=payload, timeout=5)
                response.raise_for_status()
                response_payload = response.json()
                if response_payload.get("organization_id"):
                    self.organization_id = response_payload["organization_id"]
                    self.flow_manager.organization_id = self.organization_id
                    if hasattr(self, "web_inspection"):
                        self.web_inspection.update_context(organization_id=self.organization_id)
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
            response = self.api_client.request("POST", self.devices_url, json_body=devices, timeout=10)
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
        if hasattr(self, "capture_backend"):
            self.capture_backend.stop()
        if hasattr(self, "web_inspection"):
            self.web_inspection.stop()
        self.flow_manager.stop()
        self.device_inventory.save_inventory()
        sys.exit(0)

    def start(self, timeout=None):
        print(f"{Fore.BLUE}[*] Netvisor Hybrid Agent Starting...")
        success, error = self.capture_backend.start(self.process_packet, timeout=timeout)
        if not success and self.capture_backend.backend_name != "scapy":
            logger.warning("Primary capture backend failed: %s. Falling back to Scapy.", error)
            self.capture_backend.stop()
            self.capture_backend = build_capture_backend(
                role="agent",
                interface=self.capture_interface,
                requested_backend="scapy",
            )
            success, error = self.capture_backend.start(self.process_packet, timeout=timeout)
        if not success and error:
            logger.error("Capture backend failed: %s", error)

def main(config_path=DEFAULT_CONFIG_PATH) -> None:
    parser = argparse.ArgumentParser(description="NetVisor Agent")
    parser.add_argument("--health-check", action="store_true", help="Print a startup health snapshot and exit.")
    parser.add_argument("--reset-enrollment", action="store_true", help="Clear stored signed credentials and exit.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Packet sniff timeout in seconds. Omit to run continuously until interrupted.",
    )
    args = parser.parse_args()

    if args.health_check or args.reset_enrollment:
        agent = NetworkAgent(config_path, start_background_workers=False)
        if args.reset_enrollment:
            agent.api_client.reset_enrollment()
        snapshot = agent.status_snapshot()
        snapshot["ready"] = bool(agent.api_client.status_snapshot().get("has_credentials"))
        snapshot["enrollment_required"] = not snapshot["ready"]
        print(json.dumps(snapshot, indent=2, sort_keys=True))
        sys.exit(0)

    agent = NetworkAgent(config_path)
    try:
        agent.start(timeout=args.timeout)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down Netvisor Agent...{Style.RESET_ALL}")
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
