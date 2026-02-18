import requests
import datetime
import socket

# Local IP detected: 10.31.205.96
LOCAL_IP = "10.31.205.96"
SERVER_URL = "http://127.0.0.1:8000/api/v1/collect/packet"
HEADERS = {"X-API-Key": "soc-agent-key-2026"}

def show_device():
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    hostname = socket.gethostname()
    
    # Simulate a high-fidelity "Fluent" log
    record = {
        "time": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": LOCAL_IP,
        "dst_ip": "8.8.8.8",
        "domain": "google.com",
        "protocol": "TCP",
        "size": 512,
        "port": "443",
        "risk_score": 0,
        "entropy": 3.5,
        "severity": "LOW",
        "device_name": hostname,
        "device_type": "PC",
        "os_family": "Windows",
        "brand": "Microsoft"
    }
    
    try:
        res = requests.post(SERVER_URL, json=record, headers=HEADERS, timeout=2.0)
        if res.status_code == 200:
            print(f"[SUCCESS] Injected record for {LOCAL_IP} ({hostname})")
        else:
            print(f"[FAIL] Server returned {res.status_code}: {res.text}")
    except Exception as e:
        print(f"[ERROR] Could not connect to server: {e}")

if __name__ == "__main__":
    show_device()
