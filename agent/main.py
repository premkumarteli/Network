import sys
import csv
import os
import threading
import time
import requests
import queue
import socket
import math
import collections
import json
import random
import platform
import signal
import subprocess
import re
import uuid
import psutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from scapy.all import sniff, IP, DNS, DNSQR, UDP, TCP, Ether
from colorama import Fore, Style, init
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent directory to sys.path to allow importing modules from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from services.detector import AnomalyDetector

# =========================================================
# THREAD SAFE DEVICE INVENTORY (PERSISTENT)
# =========================================================

class DeviceInventory:
    def __init__(self, storage_file="device_inventory.json"):
        self.lock = threading.Lock()
        self.storage_file = storage_file
        self.devices = {}
        self.load_inventory()
        # Start background save worker (Performance Fix)
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
        """Batched save every 30 seconds to reduce I/O"""
        while True:
            time.sleep(30)
            self.save_inventory()

    def save_inventory(self):
        try:
            with self.lock: # Ensure thread safety during dump
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
            # Removed direct save_inventory() call for performance

    def get(self, ip):
        return self.devices.get(ip)


# =========================================================
# MAIN AGENT
# =========================================================

class NetworkAgent:

    def __init__(self, config_path="core/config.json"):
        self.config = self._load_config(config_path)

        url_config = self.config.get("server_url", "http://127.0.0.1:8000")
        if "/api/v1/collect" in url_config:
            base = url_config.split("/api/v1/collect")[0]
        else:
            base = url_config.rstrip("/")

        self.server_url = base + "/api/v1/collect/packet"
        self.batch_url = base + "/api/v1/collect/batch"
        self.heartbeat_url = base + "/api/v1/collect/heartbeat"
        self.policy_url = base + "/api/v1/policy"

        self.agent_id = self._init_agent_id()
        self.organization_id = self.config.get("organization_id", "default-org-id") # Should be provided in config
        self.api_key = os.getenv("AGENT_API_KEY") or self.config.get("api_key", "soc-agent-key-2026")
        self.headers = {"X-API-Key": self.api_key}

        self.policy = {
            "blocked_domains": [],
            "vpn_restriction": False,
            "alert_threshold": 70
        }

        self.batch_size = 10
        self.max_q = 10000
        self.bpf_filter = "udp port 53 or tcp port 53"

        self.is_running = True
        self.remote_active = True
        self.verbose = True
        self.dropped_packets = 0
        
        self.device_inventory = DeviceInventory()
        self.probing_ips = set()
        
        # OUI Vendor Cache
        self.vendor_cache = {
            "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", 
            "00:1C:14": "VMware", "08:00:27": "Oracle VirtualBox", 
            "00:15:5D": "Microsoft Hyper-V", "DC:A6": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi", "D8:3A:DD": "Ubiquiti", 
            "F0:9F:C2": "Ubiquiti", "00:11:32": "Synology"
        }

        # Risk Analysis Engine (ML-Enhanced)
        # self.detector = AnomalyDetector(risk_threshold=20)
        
        # Deduplication
        self.dedup_lock = threading.Lock()
        self.recent_queries = {}
        self.dedup_window = 5
        
        # Cleanup Worker
        # Queues and Thread Pools
        self.upload_q = queue.Queue(maxsize=self.max_q)
        self.log_q = queue.Queue(maxsize=self.max_q)
        self.discovery_pool = ThreadPoolExecutor(max_workers=10)

        # Start Workers
        threading.Thread(target=self._dedup_cleanup, daemon=True).start()
        threading.Thread(target=self._upload_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()
        threading.Thread(target=self._discovery_engine, daemon=True).start()
        threading.Thread(target=self._log_worker, daemon=True).start()
        
        self._register_agent()

    def _dedup_cleanup(self):
        while self.is_running:
            time.sleep(60)
            try:
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.dedup_window)
                with self.dedup_lock:
                    # Prune old entries
                    keys_to_del = [k for k, v in self.recent_queries.items() if v < cutoff]
                    for k in keys_to_del:
                        del self.recent_queries[k]
            except:
                pass

    def _init_agent_id(self):
        """Ensures a persistent unique Agent ID"""
        id_file = "agent_id.txt"
        if os.path.exists(id_file):
            with open(id_file, "r") as f:
                return f.read().strip()
        
        # If not exists, check config
        cid = self.config.get("agent_id")
        if cid and cid != "GATEWAY_SENSE_01":
            return cid
            
        # Generate new one
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
                    "version": "v2.2-professional",
                    "time": datetime.now().isoformat(),
                    "organization_id": self.organization_id
                }
                r = requests.post(self.server_url.replace("/packet", "/register"), json=payload, headers=self.headers, timeout=2)
                r.raise_for_status()
                res = r.json()
                if res.get("organization_id"):
                    self.organization_id = res["organization_id"]
                    logger.info(f"Agent synced with Organization: {self.organization_id}")
                print(f"{Fore.GREEN}[+] Professional Agent Registered Successfully")
                return
            except Exception as e:
                logger.warning(f"Registration failed: {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)

    # ======================== UTILS ==========================

    def detect_os(self, ttl):
        if ttl <= 64: return "Linux/Android"
        if ttl <= 128: return "Windows"
        return "Network Device"

    def resolve_vendor(self, mac_address):
        if not mac_address or len(mac_address) < 8: return "Unknown"
        mac_upper = mac_address.upper().replace("-", ":")
        prefix = mac_upper[:8]
        if prefix in self.vendor_cache: return self.vendor_cache[prefix]
        # Fallback to API in future if needed
        return "Unknown"

    def detect_device_type(self, os_fam, vendor, domains):
        vendor = vendor.lower()
        if "apple" in vendor or "samsung" in vendor: return "Mobile/Tablet"
        if "synology" in vendor or "qnap" in vendor: return "NAS"
        if "printer" in vendor or "epson" in vendor or "hp" in vendor: return "Printer"
        if "vmware" in vendor or "oracle" in vendor: return "Virtual Machine"
        return "Unknown"



    # ======================== DISCOVERY ======================

    def _async_enrich(self, ip):
        if ip in self.probing_ips: return
        # Limit to local private ranges
        if not ip.startswith(("192.168.", "10.", "172.")): return
        self.probing_ips.add(ip)
        
        # Submit NetBIOS probe to thread pool
        if platform.system() == "Windows":
            self.discovery_pool.submit(self._probe_netbios, ip)

    def _probe_netbios(self, ip):
        try:
            output = subprocess.check_output(f"nbtstat -A {ip}", shell=True, timeout=2).decode(errors="ignore")
            match = re.search(r'([A-Z0-9\-]+)\s+\<00\>\s+UNIQUE', output)
            if match:
                self.device_inventory.update(ip, hostname=match.group(1), confidence="high")
        except: pass
        finally:
            self.probing_ips.discard(ip)

    def _parse_arp_table(self):
        """Cross-platform ARP table parsing"""
        sys = platform.system()
        arp_map = {}
        
        try:
            if sys == "Windows":
                cmd = "arp -a"
                regex = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})'
            else: # Linux/MacOS
                cmd = "arp -a" if sys == "Darwin" else "arp -n"
                # Linux: 1.2.3.4            ether   00:00:00:00:00:00   C                     eth0
                # Mac: ? (1.2.3.4) at 00:00:00:00:00:00 on en0 ifscope [ethernet]
                regex = r'\(?(\d+\.\d+\.\d+\.\d+)\)?.*([0-9a-f:]{17})'

            output = subprocess.check_output(cmd, shell=True).decode(errors="ignore")
            
            for line in output.split('\n'):
                match = re.search(regex, line, re.I)
                if match:
                    ip, mac = match.groups()
                    mac = mac.replace('-', ':').lower()
                    arp_map[ip] = mac
                    
        except Exception as e:
            logger.debug(f"ARP parse error: {e}")
            
        return arp_map

    def _discovery_engine(self):
        print(f"{Fore.BLUE}[!] Enterprise Discovery Engine: ONLINE")
        # Self-identification
        try:
            self_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,48,8)][::-1])
            self.device_inventory.update(self._get_local_ip(), mac=self_mac, hostname=socket.gethostname(), vendor="Self", confidence="high")
        except: pass

        while self.is_running:
            try:
                # ARP Scan
                arp_data = self._parse_arp_table()
                for ip, mac in arp_data.items():
                    vendor = self.resolve_vendor(mac)
                    self.device_inventory.update(ip, mac=mac, vendor=vendor)
            except: pass
            
            time.sleep(60) # Adaptive interval can be added here

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except: return "127.0.0.1"

    # ======================== WORKERS ========================

    def get_device_label(self, ip, is_local_ip=False, is_response=False):
        if not hasattr(self, 'device_inventory'):
             return f"{Style.DIM}{ip}{Style.RESET_ALL}"
             
        dev = self.device_inventory.get(ip)
        if dev and dev["hostname"] != "Unknown":
            label = dev["hostname"]
            if dev["confidence"] == "high":
                return f"{Fore.GREEN}{label}{Style.RESET_ALL}"
            return f"{Fore.CYAN}{label}{Style.RESET_ALL}"
        
        # If gateway
        if ip.endswith(".1") or ip.endswith(".254"):
            return f"{Fore.MAGENTA}GATEWAY{Style.RESET_ALL}"
            
        return f"{Style.DIM}{ip}{Style.RESET_ALL}"

    def process_packet(self, packet):
        if not self.remote_active: return

        # DEBUG: Print dot for every packet to verify capture
        print(".", end="", flush=True) 
                
        try:
            # Check for candidate DNS packets that are being missed
            # if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
            #    if not packet.haslayer(DNS):
            #        print(f"UDP 53: {packet.summary()}")
            
            if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(DNSQR):
                # Sampling logic removed or fixed
                # if random.random() > 0.5: return 

                now_utc = datetime.now(timezone.utc)
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                is_response = (packet[DNS].qr == 1)
                
                try: domain = packet[DNSQR].qname.decode(errors="ignore").strip(".").lower()
                except: return

                if not domain or len(domain) > 255: return
                
                # Policy Enforcement: Blocked Domains
                if domain in self.policy.get("blocked_domains", []):
                    if self.verbose:
                        print(f"{Fore.RED}[BLOCK]{Style.RESET_ALL} Prevented access to {domain}")
                    return

                port = 53
                proto = "UDP"
                if packet.haslayer(TCP): proto = "TCP"; port = packet[TCP].dport
                elif packet.haslayer(UDP): port = packet[UDP].dport

                # Deduplication
                key = (src_ip, domain, now_utc.second)
                with self.dedup_lock:
                    if key in self.recent_queries: return
                    self.recent_queries[key] = now_utc

                # Enrichment
                ttl = packet[IP].ttl
                os_family = self.detect_os(ttl)
                
                # Device Inventory (Disabled for now to prevent crash)
                # device = self.device_inventory.get(src_ip)
                device = None
                
                if not device:
                    # self._async_enrich(src_ip)
                    mac, vendor, name, conf = "-", "Unknown", "Unknown", "low"
                    d_type = self.detect_device_type(os_family, vendor, [domain])
                else:
                    mac = device["mac"]
                    vendor = device["vendor"]
                    name = device["hostname"]
                    conf = device["confidence"]
                    d_type = device["type"]

                # mDNS/NBNS snooping
                potential_name = None
                if domain.endswith(".local") or ".nbns" in domain:
                    potential_name = domain.split('.')[0].upper()
                    # self.device_inventory.update(src_ip, hostname=potential_name, confidence="high")

                name = potential_name or name
                
                # ML-Enhanced Analysis (Disabled)
                # risk_score, entropy_val, severity, ml_prob = self.detector.analyze_packet(domain, src_ip, 0)
                risk_score, entropy_val, severity, ml_prob = 0, 0.0, "LOW", 0.0

                risk_label = f"{Fore.RED}[{severity}]{Style.RESET_ALL}" if severity != "LOW" else ""

                record = {
                    "time": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip, 
                    "dst_ip": dst_ip,
                    "domain": domain,
                    "protocol": proto,
                    "size": len(packet),
                    "port": str(port),
                    "risk_score": risk_score,
                    "entropy": round(entropy_val, 2),
                    "severity": severity,
                    "device_name": name,
                    "device_type": d_type,
                    "os_family": os_family,
                    "brand": vendor,
                    "mac_address": mac,
                    "identity_confidence": conf,
                    "organization_id": self.organization_id
                }
                
                # Queueing
                if not self.log_q.full():
                    self.log_q.put([record["time"], src_ip, domain, self.agent_id, severity, risk_score, round(entropy_val, 2)])
                
                if not self.upload_q.full():
                    self.upload_q.put(record)

                if self.verbose:
                    out = self.get_device_label(src_ip)
                    out += f" {Style.BRIGHT}{Fore.YELLOW} -> {domain} {Style.RESET_ALL}"
                    if severity != "LOW": out += f" {risk_label}"
                    if os_family != "Unknown": out += f" {Style.DIM}[{os_family}|{vendor}]{Style.RESET_ALL}"
                    print(out)

        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def _upload_worker(self):
        batch = []
        last_send = time.time()
        retry_delay = 1  # Start with 1s delay
        
        while self.is_running:
            try:
                # Optimized: Reduce timeout to avoid blocking too long if queue is empty
                record = self.upload_q.get(timeout=0.5)
                batch.append(record)
                self.upload_q.task_done()
            except queue.Empty: 
                pass
            
            # Condition to send: Batch full OR time elapsed (and batch has data)
            if len(batch) >= self.batch_size or (time.time() - last_send > 2 and batch):
                try:
                    r = requests.post(self.batch_url, json=batch, headers=self.headers, timeout=2.0)
                    r.raise_for_status()
                    
                    # Success: Reset batch and retry delay
                    batch = []
                    last_send = time.time()
                    retry_delay = 1 
                except Exception as e:
                    # Failure: Exponential Backoff
                    print(f"Upload failed: {e}. Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60) # Max 60s wait
                    # Keep batch to retry next loop

    def upload(self, record):
        try: requests.post(self.server_url, json=record, headers=self.headers, timeout=1.0)
        except Exception as e: logger.error(f"Single upload failed: {e}")

    def _heartbeat_worker(self):
        while self.is_running:
            try:
                # Metrics
                cpu = psutil.cpu_percent(interval=None)
                ram = psutil.virtual_memory().percent
                
                payload = {
                    "agent_id": self.agent_id,
                    "status": "online" if self.remote_active else "paused",
                    "dropped_packets": self.dropped_packets,
                    "cpu_usage": cpu,
                    "ram_usage": ram,
                    "inventory_size": len(self.device_inventory.devices),
                    "time": datetime.now().isoformat()
                }
                r = requests.post(self.heartbeat_url, json=payload, headers=self.headers, timeout=2)
                r.raise_for_status()
                logger.debug("Heartbeat sent successfully")
                
                # Periodic Policy Fetch
                self._fetch_policy()
            except Exception as e: 
                logger.warning(f"Heartbeat/Policy fetch failed: {e}")
            
            # Use adaptive sleep or fixed interval
            time.sleep(30)

    def _fetch_policy(self):
        try:
            r = requests.get(f"{self.policy_url}/{self.organization_id}", headers=self.headers, timeout=2)
            if r.status_code == 200:
                new_policy = r.json()
                if new_policy != self.policy:
                    self.policy = new_policy
                    print(f"{Fore.CYAN}[+] Policy Updated: {len(self.policy.get('blocked_domains', []))} blocked domains")
        except:
            pass
            
    def _log_worker(self):
        log_file = "local_capture_log.csv"
        buffer = []
        last_flush = time.time()
        while self.is_running:
            try:
                data = self.log_q.get(timeout=1)
                buffer.append(data)
                self.log_q.task_done()
            except: pass
            
            if len(buffer) >= 20 or (time.time() - last_flush > 5 and buffer):
                try:
                    with open(log_file, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerows(buffer)
                    buffer = []
                    last_flush = time.time()
                except Exception as e:
                    logger.error(f"Log flush failed: {e}")

    def stop(self, signum=None, frame=None):
        print(f"\n{Fore.YELLOW}[!] Shutting down Enterprise Agent...")
        self.device_inventory.save_inventory()
        self.is_running = False
        time.sleep(1)
        sys.exit(0)

    def start(self):
        from scapy.all import conf
        print(f"{Fore.CYAN}[*] Available Interfaces:")
        print(conf.iface)
        
        print(f"{Fore.BLUE}{'='*80}\n   ELITE SOC AGENT: ENTERPRISE EDITION | Filter: {self.bpf_filter}\n{'='*80}")
        print(f"{Fore.GREEN}[*] Sniffing started... Generate DNS traffic to see output.")
        # Try without BPF filter first to debug VLAN issues
        sniff(filter=self.bpf_filter, prn=self.process_packet, store=False, promisc=True)

if __name__ == "__main__":
    NetworkAgent("core/config.json").start()
