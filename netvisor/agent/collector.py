import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple, Optional
from scapy.all import IP, TCP, UDP
from datetime import datetime, timezone

FlowKey = Tuple[str, str, int, int, str]

@dataclass
class FlowState:
    start_time: float
    last_seen: float
    packet_count: int
    byte_count: int
    domain: Optional[str] = None

class FlowManager:
    def __init__(self, agent_id, organization_id, on_flow_expired):
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.on_flow_expired = on_flow_expired
        self._flows: Dict[FlowKey, FlowState] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        threading.Thread(target=self._expiry_worker, daemon=True).start()

    def update_from_packet(self, packet):
        if not packet.haslayer(IP): return
        ip = packet[IP]
        if packet.haslayer(TCP):
            proto, sport, dport = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        else:
            proto, sport, dport = str(ip.proto), 0, 0

        key = (ip.src, ip.dst, sport, dport, proto)
        now = time.time()
        with self._lock:
            state = self._flows.get(key)
            if not state:
                self._flows[key] = FlowState(now, now, 1, len(packet))
            else:
                state.last_seen = now
                state.packet_count += 1
                state.byte_count += len(packet)
                if hasattr(packet, 'captured_domain'):
                    state.domain = packet.captured_domain

    def _expiry_worker(self):
        while not self._stop_event.is_set():
            now = time.time()
            expired = {}
            with self._lock:
                for key, state in list(self._flows.items()):
                    timeout = 60 if key[4] == "TCP" else 30
                    if now - state.last_seen >= timeout:
                        expired[key] = state
                        del self._flows[key]
            for key, state in expired.items():
                self.on_flow_expired(self._build_summary(key, state))
            time.sleep(5)

    def _build_summary(self, key, state):
        return {
            "src_ip": key[0], "dst_ip": key[1], "src_port": key[2], "dst_port": key[3],
            "protocol": key[4], "packet_count": state.packet_count, "byte_count": state.byte_count,
            "start_time": datetime.fromtimestamp(state.start_time, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(state.last_seen, tz=timezone.utc).isoformat(),
            "duration": state.last_seen - state.start_time,
            "average_packet_size": state.byte_count / state.packet_count,
            "domain": state.domain, "agent_id": self.agent_id, "organization_id": self.organization_id
        }
