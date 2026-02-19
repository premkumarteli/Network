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

init(autoreset=True)

# =========================================================
# THREAD SAFE DEVICE INVENTORY (PERSISTENT)
# =========================================================

class DeviceInventory:
    def __init__(self, storage_file="device_inventory.json"):
        self.lock = threading.Lock()
        self.storage_file = storage_file
        self.devices = {}
        self.load_inventory()

    def load_inventory(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    self.devices = json.load(f)
                    print(f"{Fore.GREEN}[+] Loaded {len(self.devices)} devices from inventory.")
            except:
                pass

    def save_inventory(self):
        try:
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
            self.save_inventory()

    def get(self, ip):
        with self.lock:
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

        self.agent_id = self.config.get("agent_id", "GATEWAY_SENSE_01")
        self.api_key = self.config.get("api_key", "soc-agent-key-2026")
        self.headers = {"X-API-Key": self.api_key}

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

        # Risk Analysis State
        self.risk_threshold = 20
        self.start_time = time.time()
        self.ip_counts = collections.defaultdict(int)
        self.nx_counts = collections.defaultdict(int)
        self.unique_domains = collections.defaultdict(set)
        self.counter_lock = threading.Lock()
        
        # Deduplication
        self.dedup_lock = threading.Lock()
        self.recent_queries = {}
        self.dedup_window = 5

        self.upload_q = queue.Queue(maxsize=self.max_q)
        self.log_q = queue.Queue(maxsize=self.max_q)
        
        # NetBIOS Thread Pool
        self.discovery_pool = ThreadPoolExecutor(max_workers=10)

        signal.signal(signal.SIGINT, self.stop)

        threading.Thread(target=self._upload_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()
        threading.Thread(target=self._discovery_engine, daemon=True).start()
        threading.Thread(target=self._log_worker, daemon=True).start()
        
        self._register_agent()

    def _load_config(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _register_agent(self):
        try:
            payload = {
                "agent_id": self.agent_id,
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "version": "v2.1-enterprise"
            }
            requests.post(self.server_url.replace("/packet", "/register"), json=payload, headers=self.headers, timeout=2)
            print(f"{Fore.GREEN}[+] Enterprise Agent Registered")
        except:
            pass

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

    def calculate_entropy(self, data):
        if not data: return 0
        counter = collections.Counter(data)
        total = len(data)
        return -sum((count/total) * math.log2(count/total) for count in counter.values())

    def get_risk_score(self, domain, src_ip, rcode=0):
        score = 0
        parts = domain.split('.')
        longest_part = max(parts, key=len) if parts else domain
        
        if len(longest_part) > 25: score += 2
        if sum(c.isdigit() for c in longest_part) > 5: score += 2
        
        ent = self.calculate_entropy(longest_part)
        if ent > 4.6: score += 3
        
        with self.counter_lock:
            if rcode != 0:
                self.nx_counts[src_ip] += 1
                if self.nx_counts[src_ip] > 20: score += 2

            self.ip_counts[src_ip] += 1
            self.unique_domains[src_ip].add(domain)
            if len(self.unique_domains[src_ip]) > 50: score += 3
            
            elapsed = time.time() - self.start_time
            if elapsed > 300:
                self.ip_counts.clear()
                self.nx_counts.clear()
                self.unique_domains.clear()
                self.start_time = time.time()
                elapsed = 0.1
                
            rate = self.ip_counts[src_ip] / (max(elapsed, 1) / 60)
            if rate > 200: score += 2
            
        severity = "LOW"
        if score >= self.risk_threshold: severity = "HIGH"
        elif score >= max(1, self.risk_threshold // 2): severity = "MEDIUM"
            
        return score, ent, severity

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
            pass # Silent fail in production
            
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
        try:
            if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(DNSQR):
                if random.random() > 0.5: # 50% Sampling for performance
                    pass # Or return
                    
                now_utc = datetime.now(timezone.utc)
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                is_response = (packet[DNS].qr == 1)
                
                try: domain = packet[DNSQR].qname.decode(errors="ignore").strip(".").lower()
                except: return

                if not domain or len(domain) > 255: return

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
                
                device = self.device_inventory.get(src_ip)
                if not device:
                    self._async_enrich(src_ip)
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
                    self.device_inventory.update(src_ip, hostname=potential_name, confidence="high")

                name = potential_name or name
                risk_score, entropy_val, severity = self.get_risk_score(domain, src_ip, 0) # rcode 0 for query
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
                    "identity_confidence": conf
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
            pass

    def _upload_worker(self):
        batch = []
        last_send = time.time()
        while self.is_running:
            try:
                record = self.upload_q.get(timeout=1)
                batch.append(record)
                self.upload_q.task_done()
            except queue.Empty: pass
            
            if len(batch) >= self.batch_size or (time.time() - last_send > 2 and batch):
                try:
                    r = requests.post(self.batch_url, json=batch, headers=self.headers, timeout=2.0)
                    r.raise_for_status()
                    batch = []
                    last_send = time.time()
                except:
                    for r in batch: self.upload(r) # Fallback
                    batch = []

    def upload(self, record):
        try: requests.post(self.server_url, json=record, headers=self.headers, timeout=1.0)
        except: pass

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
                    "inventory_size": len(self.device_inventory.devices)
                }
                requests.post(self.heartbeat_url, json=payload, headers=self.headers, timeout=1)
            except: pass
            time.sleep(30)
            
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
                except: pass

    def stop(self, signum=None, frame=None):
        print(f"\n{Fore.YELLOW}[!] Shutting down Enterprise Agent...")
        self.device_inventory.save_inventory()
        self.is_running = False
        time.sleep(1)
        sys.exit(0)

    def start(self):
        print(f"{Fore.BLUE}{'='*80}\n   ELITE SOC AGENT: ENTERPRISE EDITION | Filter: {self.bpf_filter}\n{'='*80}")
        sniff(filter=self.bpf_filter, prn=self.process_packet, store=False, promisc=True)

if __name__ == "__main__":
    NetworkAgent("core/config.json").start()
