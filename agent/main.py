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
from datetime import datetime, timezone, timedelta
from scapy.all import sniff, IP, DNS, DNSQR, get_if_list, get_if_addr, TCP, UDP
from colorama import Fore, Style, init

init(autoreset=True)

class NetworkAgent:
    def __init__(self, config_path="core/config.json"):
        self.config = self._load_config(config_path)

        server_url = self.config.get("server_url", "http://127.0.0.1:8000/api/v1/collect/packet")
        base = server_url.rstrip("/")
        if "/api/v1/collect" in base:
            base = base.split("/api/v1/collect", 1)[0]
        self.server_url = base + "/api/v1/collect/packet"
        self.heartbeat_url = self.config.get("heartbeat_url", base + "/api/v1/collect/heartbeat")

        self.agent_id = self.config.get("agent_id", "GATEWAY_SENSE_01")
        self.dedup_window = self.config.get("dedup_window", 5)
        self.log_file = self.config.get("log_file", "local_capture_log.csv")
        self.verbose = self.config.get("verbose", True)
        self.batch_size = self.config.get("batch_size", 10)
        self.max_q = self.config.get("max_queue_size", 10000)
        self.risk_threshold = max(1, int(self.config.get("risk_threshold", 6)))
        self.bpf_filter = self.config.get("bpf_filter", "udp port 53 or tcp port 53")
        self.sample_rate = float(self.config.get("sample_rate", 1.0))
        self.sample_rate = max(0.0, min(self.sample_rate, 1.0))
        self.api_key = self.config.get("api_key", "soc-agent-key-2026")
        self.headers = {"X-API-Key": self.api_key}
        
        self.is_running = True
        self.remote_active = True  # Controlled by Server Toggle
        self.recent_queries = {}
        self.dedup_lock = threading.Lock()
        
        self._init_local_log()
        self.hostname = socket.gethostname()
        self.local_ips = self._get_all_local_ips()
        
        # --- FEATURE: Manual Device Mapping ---
        # Add IPs here that refuse to resolve (like your Gateway/Router)
        self.known_devices = {
            "10.162.162.4": f"{Fore.MAGENTA}GATEWAY/DNS{Style.RESET_ALL}",
            "8.8.8.8": f"{Fore.MAGENTA}GOOGLE_DNS{Style.RESET_ALL}",
            "1.1.1.1": f"{Fore.MAGENTA}CLOUDFLARE{Style.RESET_ALL}"
        }
        
        self.device_cache = self.known_devices.copy()
        
        # --- NEW: Fluent Metadata ---
        self.device_meta = {} # IP -> {type, os, brand}
        
        # Simple OUI Database (Mock for Fluent feel)
        self.oui_db = {
            "00:0c:29": "VMware", "08:00:27": "Oracle/VirtualBox",
            "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
            "70:ee:50": "Apple", "00:1c:b3": "Apple", "ac:bc:32": "Apple",
            "60:f2:62": "Samsung", "f4:0e:22": "Samsung",
            "e4:5f:01": "D-Link", "00:08:5d": "Microsoft"
        }

        # Pre-fill cache for MYSELF
        for ip in self.local_ips:
            self.device_cache[ip] = f"{Fore.CYAN}{self.hostname}{Style.RESET_ALL}"
            
        self.dropped_packets = 0  
        
        # Elite Synchronization & Trackers
        self.counter_lock = threading.Lock()
        self.ip_counts = collections.Counter()
        self.nx_counts = collections.Counter()
        self.unique_domains = collections.defaultdict(set)
        self.start_time = time.time()
        
        # Elite Queues
        self.upload_q = queue.Queue(maxsize=self.max_q)
        self.log_q = queue.Queue(maxsize=self.max_q)
        
        signal.signal(signal.SIGINT, self.stop)
        
        # Background Workers
        threading.Thread(target=self._upload_worker, daemon=True).start()
        threading.Thread(target=self._log_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_worker, daemon=True).start()
        threading.Thread(target=self._cleanup_worker, daemon=True).start()
        threading.Thread(target=self._remote_config_worker, daemon=True).start()
        
        self._register_agent()

    def _load_config(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    return json.load(f)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Config Error: {e}. Using defaults.")
        return {}

    def _init_local_log(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "source_ip", "domain", "agent_id", "severity", "risk_score", "entropy"])

    def _get_all_local_ips(self):
        """Get all local IP addresses to identify 'myself' immediately."""
        ips = set()
        ips.add("127.0.0.1")
        ips.add("::1")
        try:
            _, _, ip_list = socket.gethostbyname_ex(self.hostname)
            for ip in ip_list:
                ips.add(ip)
        except: pass
        try:
            for iface in get_if_list():
                try:
                    addr = get_if_addr(iface)
                    if addr and addr != "0.0.0.0": ips.add(addr)
                except: pass
        except: pass
        return list(ips)

    def get_device_label(self, ip, is_response=False):
        """Get label. is_response=True helps identify DNS servers."""
        if ip in self.device_cache:
            return self.device_cache[ip]
        
        # Fallback 1: If it's a DNS Response, it's likely a DNS Server
        if is_response:
            label = f"{Fore.MAGENTA}DNS_SERVER{Style.RESET_ALL}"
            self.device_cache[ip] = label
            return label

        # Fallback 2: Check standard ranges
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            label = f"{Fore.YELLOW}{ip}{Style.RESET_ALL}"
            self.device_cache[ip] = label 
            threading.Thread(target=self._async_resolve, args=(ip, Fore.YELLOW), daemon=True).start()
        else:
            label = f"{Fore.CYAN}EXTERNAL{Style.RESET_ALL}"
            self.device_cache[ip] = label

        return self.device_cache[ip]

    def _async_resolve(self, ip, color):
        try:
            name = socket.gethostbyaddr(ip)[0].split('.')[0].upper()
            self.device_cache[ip] = f"{color}{name}{Style.RESET_ALL}"
        except:
            pass

    def detect_os(self, ttl):
        """Simple TTL-based OS Fingerprinting."""
        if ttl <= 64: return "Linux/Android"
        if ttl <= 128: return "Windows"
        return "Network Device"

    def resolve_vendor(self, mac):
        """OUI Lookup."""
        if not mac: return "Unknown"
        prefix = mac.lower()[:8]
        return self.oui_db.get(prefix, "Unknown")

    def detect_device_type(self, os_fam, brand, domain_list):
        """Heuristic to guess device type."""
        os_fam = os_fam.lower()
        brand = brand.lower()
        
        if "apple" in brand or "samsung" in brand:
             # Check for common mobile domains or OS patterns
             if "android" in os_fam: return "Mobile"
             return "Smart Device"
        if "windows" in os_fam or "linux" in os_fam: return "PC"
        if "vmware" in brand or "oracle" in brand: return "Virtual Machine"
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
        high_threshold = self.risk_threshold
        medium_threshold = max(1, self.risk_threshold // 2)
        if score >= high_threshold:
            severity = "HIGH"
        elif score >= medium_threshold:
            severity = "MEDIUM"
            
        return score, ent, severity

    def _register_agent(self):
        try:
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            reg_data = {
                "agent_id": self.agent_id,
                "os": platform.system(),
                "hostname": self.hostname,
                "version": "v1.7-labeled",
                "time": now_str
            }
            requests.post(self.server_url.replace("/packet", "/register"), json=reg_data, headers=self.headers, timeout=2.0)
            print(f"{Fore.GREEN}[+] Agent Registered with SOC Server")
        except: pass

    def _upload_worker(self):
        batch = []
        last_send = time.time()
        while self.is_running:
            try:
                record = self.upload_q.get(timeout=1.0)
                batch.append(record)
                self.upload_q.task_done()
            except queue.Empty: pass
            
            if len(batch) >= self.batch_size or (time.time() - last_send > 2 and batch):
                try:
                    requests.post(self.server_url.replace("/packet", "/batch"), json=batch, headers=self.headers, timeout=2.0)
                    batch = []
                    last_send = time.time()
                except:
                    for r in batch: self.upload(r)
                    batch = []

    def _log_worker(self):
        buffer = []
        last_flush = time.time()
        while self.is_running:
            try:
                data = self.log_q.get(timeout=1.0)
                buffer.append(data)
                self.log_q.task_done()
            except queue.Empty: pass
            
            if len(buffer) >= 20 or (time.time() - last_flush > 5 and buffer):
                try:
                    with open(self.log_file, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerows(buffer)
                    buffer = []
                    last_flush = time.time()
                except: pass

    def _heartbeat_worker(self):
        while self.is_running:
            try:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                heartbeat = {
                    "agent_id": self.agent_id,
                    "status": "online" if self.remote_active else "paused",
                    "dropped_packets": self.dropped_packets,
                    "time": now_str
                }
                requests.post(self.heartbeat_url, json=heartbeat, headers=self.headers, timeout=1.0)
            except: pass
            time.sleep(30)

    def _remote_config_worker(self):
        """Polls server to check if monitoring should be active."""
        config_url = self.server_url.replace("/collect/packet", "/settings/system/status")
        # Initial check to print state immediately
        try:
            r = requests.get(config_url, headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                self.remote_active = r.json().get("active", True)
                status = "RESUMED" if self.remote_active else "PAUSED"
                color = Fore.GREEN if self.remote_active else Fore.YELLOW
                print(f"{color}[!] Monitoring Engine: {status}")
        except: pass

        while self.is_running:
            try:
                r = requests.get(config_url, headers=self.headers, timeout=2.0)
                if r.status_code == 200:
                    data = r.json()
                    new_state = data.get("active", True)
                    if new_state != self.remote_active:
                        self.remote_active = new_state
                        status = "RESUMED" if self.remote_active else "PAUSED"
                        color = Fore.GREEN if self.remote_active else Fore.YELLOW
                        print(f"{color}[!] Monitoring Engine: {status}")
            except: pass
            time.sleep(3)

    def _cleanup_worker(self):
        last_console_heartbeat = time.time()
        while self.is_running:
            time.sleep(10)
            if time.time() - last_console_heartbeat > 60:
                status = "ACTIVE" if self.remote_active else "PAUSED"
                print(f"{Fore.BLUE}[i] SOC Agent Status: {status} | Buffer: {self.upload_q.qsize()}/{self.max_q} packets")
                last_console_heartbeat = time.time()

            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=self.dedup_window * 3)
            with self.dedup_lock:
                keys = list(self.recent_queries.keys())
                for k in keys:
                    if self.recent_queries[k] < cutoff:
                        del self.recent_queries[k]

    def process_packet(self, packet):
        if not self.remote_active:
            return
        try:
            if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(DNSQR):
                if self.sample_rate < 1.0 and random.random() > self.sample_rate:
                    return

                now_utc = datetime.now(timezone.utc)
                now_local = datetime.now()
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check if this packet is a Response (qr=1)
                is_response = (packet[DNS].qr == 1)

                try:
                    domain = packet[DNSQR].qname.decode(errors="ignore").strip(".").lower()
                except: return
                
                rcode = packet[DNS].rcode

                if not domain or len(domain) > 255: return 

                port = 53
                proto = "UDP"
                if packet.haslayer(UDP):
                    proto = "UDP"
                    port = packet[UDP].dport
                elif packet.haslayer(TCP):
                    proto = "TCP"
                    port = packet[TCP].dport

                key = (src_ip, domain, now_utc.second)
                with self.dedup_lock:
                    if key in self.recent_queries and (now_utc - self.recent_queries[key]).total_seconds() < self.dedup_window:
                        return
                    self.recent_queries[key] = now_utc

                # 🟢 NEW: Advanced Detection
                ttl = packet[IP].ttl
                os_family = self.detect_os(ttl)
                brand = self.resolve_vendor(packet.src)
                d_type = self.detect_device_type(os_family, brand, [domain])
                
                # Check for identity protocols or mDNS names
                potential_name = None
                if domain.endswith(".local") or ".nbns" in domain or ".llmnr" in domain:
                    potential_name = domain.split('.')[0].upper()
                
                risk_score, entropy_val, severity = self.get_risk_score(domain, src_ip, rcode)
                risk_label = f"{Fore.RED}[{severity} RISK]{Style.RESET_ALL}" if severity != "LOW" else ""

                record = {
                    "time": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "domain": domain,
                    "protocol": proto,
                    "size": len(packet),
                    "port": str(port),
                    "vpn_flag": False,
                    "risk_score": risk_score,
                    "entropy": round(entropy_val, 2),
                    "severity": severity,
                    "device_name": potential_name or "Unknown",
                    "device_type": d_type,
                    "os_family": os_family,
                    "brand": brand
                }

                if not self.log_q.full():
                    self.log_q.put([record["time"], src_ip, domain, self.agent_id, severity, risk_score, round(entropy_val, 2)])

                if self.verbose:
                    # PASS is_response HERE to smart-detect DNS servers
                    label = self.get_device_label(src_ip, is_response=is_response)
                    if potential_name:
                        label = f"{Fore.CYAN}{potential_name}{Style.RESET_ALL}"
                    
                    rcode_str = f" {Fore.MAGENTA}(NXDOMAIN){Style.RESET_ALL}" if rcode == 3 else ""
                    
                    out = f"[{now_local.strftime('%H:%M:%S')}] {label:<20} | {src_ip:<15} -> {Fore.GREEN}{domain}{rcode_str}"
                    if risk_label:
                        out += f" {risk_label} (Risk: {risk_score}, Ent: {record['entropy']})"
                    
                    # Fluent touch: appended metadata
                    if potential_name or d_type != "Unknown":
                        out += f" {Style.DIM}[{os_family} | {brand}]{Style.RESET_ALL}"

                    if random.random() < 0.3:
                        print(out, flush=True)

                if not self.upload_q.full():
                    self.upload_q.put(record)
                else:
                    self.dropped_packets += 1
                    if random.random() < 0.05:
                        print(f"{Fore.RED}[!] Upload queue FULL — packets dropping!")
        except Exception as e: 
            if self.is_running and random.random() < 0.01:
                print(f"{Fore.RED}[X] Sniff Error: {e}")

    def upload(self, record):
        try: requests.post(self.server_url, json=record, headers=self.headers, timeout=1.0)
        except: pass

    def stop(self, signum=None, frame=None):
        print(f"\n{Fore.YELLOW}[!] Shutting down SOC Agent...")
        self.is_running = False
        time.sleep(1)
        sys.exit(0)

    def start(self):
        print(f"{Fore.BLUE}{'='*80}\n   ELITE SOC AGENT: {self.hostname} | Filter: {self.bpf_filter}\n{'='*80}")
        sniff(filter=self.bpf_filter, prn=self.process_packet, store=False, promisc=True)

if __name__ == "__main__":
    NetworkAgent("config.json").start()
