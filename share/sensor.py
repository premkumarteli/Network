import os
import time
import json
import socket
import requests
import threading
import queue
from datetime import datetime, timezone
from scapy.all import sniff, IP, DNS, DNSQR, TCP

# =========================================================
# LITE NETWORK SENSOR 
# =========================================================

class LiteSensor:
    def __init__(self, config_path=None):
        # Determine script directory for robust path finding
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(script_dir, "core", "config.json")
            
        self.config = self._load_config(config_path)
        
        # Connection Setup: Default to your Universal Link if config fails
        fallback_url = "https://netvisor-prem-2026.loca.lt/api/v1/collect/packet"
        server_url = self.config.get("server_url", fallback_url)
        
        self.batch_url = server_url.replace("/packet", "/batch")
        self.agent_id = self.config.get("agent_id", f"SENSOR-{socket.gethostname()}")
        self.org_id = self.config.get("organization_id", "39b6f683-3560-4178-a1cf-3652ec1b1c8a")
        self.api_key = self.config.get("api_key", "soc-agent-key-2026")
        
        self.headers = {"X-API-Key": self.api_key}
        self.upload_q = queue.Queue(maxsize=5000)
        self.is_running = True
        
        # Background Uploader
        threading.Thread(target=self._upload_worker, daemon=True).start()
        print(f"[*] Lite Sensor Initialized: {self.agent_id}")
        print(f"[*] Reporting to: {self.batch_url}")

    def _load_config(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def process_packet(self, packet):
        try:
            if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(DNSQR):
                now_utc = datetime.now(timezone.utc)
                
                try:
                    domain = packet[DNSQR].qname.decode(errors="ignore").strip(".").lower()
                except:
                    return

                if not domain: return

                port = 53
                proto = "UDP"
                if packet.haslayer(TCP): proto = "TCP"

                record = {
                    "time": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "domain": domain,
                    "protocol": proto,
                    "size": len(packet),
                    "port": str(port),
                    "agent_id": self.agent_id,
                    "organization_id": self.org_id,
                    # Minimal metadata (Sensor version doesn't do deep detection)
                    "risk_score": 0,
                    "severity": "LOW",
                    "device_name": "Remote Device",
                    "device_type": "Unknown",
                    "os_family": "Unknown",
                    "brand": "Unknown",
                    "mac_address": "-",
                    "identity_confidence": "low"
                }

                if not self.upload_q.full():
                    self.upload_q.put(record)
                    
        except Exception:
            pass

    def _upload_worker(self):
        batch = []
        while self.is_running:
            try:
                try:
                    record = self.upload_q.get(timeout=2.0)
                    batch.append(record)
                except queue.Empty:
                    pass

                if len(batch) >= 10 or (batch and len(batch) > 0 and self.upload_q.empty()):
                    try:
                        # Header to bypass LocalTunnel splash page
                        headers = self.headers.copy()
                        headers["bypass-tunnel-reminder"] = "true"
                        
                        r = requests.post(self.batch_url, json=batch, headers=headers, timeout=5)
                        if r.status_code == 200:
                            print(f"[+] Sent {len(batch)} logs to server (Response: {r.status_code})")
                        else:
                            print(f"[!] Upload failed with status {r.status_code}: {r.text[:100]}")
                        batch = []
                    except Exception as e:
                        print(f"[!] Upload failed: {e}")
                        time.sleep(5) # Backoff
            except Exception:
                time.sleep(1)

    def start(self):
        print("[*] Sniffing DNS traffic (BPF: port 53)...")
        sniff(filter="port 53", prn=self.process_packet, store=False)

if __name__ == "__main__":
    sensor = LiteSensor()
    sensor.start()
