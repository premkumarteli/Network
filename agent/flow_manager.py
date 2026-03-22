from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Tuple, Optional

from scapy.all import Ether, IP, TCP, UDP  # type: ignore


FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, protocol)


@dataclass
class FlowState:
    start_time: float
    last_seen: float
    last_flushed: float
    packet_count: int
    byte_count: int
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    @property
    def duration(self) -> float:
        if self.last_seen < self.start_time:
            return 0.0
        return self.last_seen - self.start_time

    @property
    def average_packet_size(self) -> float:
        if self.packet_count <= 0:
            return 0.0
        return self.byte_count / self.packet_count


@dataclass
class FlowSummary:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    last_seen: str
    packet_count: int
    byte_count: int
    duration: float
    average_packet_size: float
    agent_id: str
    organization_id: str
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None


class FlowManager:
    """
    Flow-based aggregation engine.

    Responsibilities:
    - Maintain in-memory table of active flows keyed by 5‑tuple.
    - Apply protocol-specific inactivity timeouts (TCP/UDP).
    - On expiration, emit immutable FlowSummary objects.
    - Ensure memory safety via periodic cleanup and max size eviction.

    Detection and risk logic are explicitly out of scope for this class.
    It only extracts structured flow features.
    """

    def __init__(
        self,
        agent_id: str,
        organization_id: str,
        on_flow_expired: Callable[[FlowSummary], None],
        tcp_timeout: int = 60,
        udp_timeout: int = 30,
        flush_interval: float = 5.0,
        max_flows: int = 50_000,
        cleanup_interval: float = 5.0,
    ) -> None:
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.on_flow_expired = on_flow_expired
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.flush_interval = flush_interval
        self.max_flows = max_flows
        self.cleanup_interval = cleanup_interval

        self._flows: Dict[FlowKey, FlowState] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        worker = threading.Thread(target=self._expiry_worker, daemon=True)
        worker.start()

    # -------- public API --------

    def stop(self) -> None:
        self._stop_event.set()

    def update_from_packet(self, packet) -> None:
        """
        Update or create a flow entry from a single packet.
        This function is intentionally lightweight and non-blocking.
        """
        # print("DEBUG: updating flow from packet")
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        if packet.haslayer(TCP):
            proto = "TCP"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        else:
            # Non-TCP/UDP flows are grouped by IP pair only
            proto = str(ip.proto)
            sport = 0
            dport = 0

        key: FlowKey = (ip.src, ip.dst, sport, dport, proto)
        now = time.time()
        size = len(packet)
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None

        with self._lock:
            state = self._flows.get(key)
            if state is None:
                # Memory safety: if table is too large, evict a small batch of oldest flows.
                if len(self._flows) >= self.max_flows:
                    self._evict_oldest_locked()

                self._flows[key] = FlowState(
                    start_time=now,
                    last_seen=now,
                    last_flushed=now,
                    packet_count=1,
                    byte_count=size,
                    domain=getattr(packet, "captured_domain", None),
                    sni=getattr(packet, "captured_sni", None),
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                )
            else:
                state.last_seen = now
                state.packet_count += 1
                state.byte_count += size
                # Capture domain if present (e.g. from DNS layer added by main agent)
                if hasattr(packet, 'captured_domain'):
                    state.domain = packet.captured_domain
                if hasattr(packet, 'captured_sni'):
                    state.sni = packet.captured_sni
                if src_mac:
                    state.src_mac = src_mac
                if dst_mac:
                    state.dst_mac = dst_mac

    # -------- internal workers --------

    def _expiry_worker(self) -> None:
        print("[*] FlowManager expiry worker started.")
        while not self._stop_event.is_set():
            try:
                # print("DEBUG: expiring flows...")
                self._expire_flows()
            except Exception as e:
                print(f"ERROR in FlowManager expiry worker: {e}")
                # Never allow expiry failures to kill the agent.
                pass
            self._stop_event.wait(self.cleanup_interval)

    def _expire_flows(self) -> None:
        now = time.time()
        expired: Dict[FlowKey, FlowState] = {}
        flushed: Dict[FlowKey, FlowState] = {}
        # print(f"DEBUG: _expire_flows checking {len(self._flows)} flows")

        with self._lock:
            for key, state in list(self._flows.items()):
                _, _, _, _, proto = key
                timeout = self.tcp_timeout if proto == "TCP" else self.udp_timeout
                if now - state.last_seen >= timeout:
                    if state.packet_count > 0:
                        expired[key] = state
                    del self._flows[key]
                elif state.packet_count > 0 and now - state.last_flushed >= self.flush_interval:
                    flushed[key] = FlowState(
                        start_time=state.start_time,
                        last_seen=state.last_seen,
                        last_flushed=state.last_flushed,
                        packet_count=state.packet_count,
                        byte_count=state.byte_count,
                        domain=state.domain,
                        sni=state.sni,
                        src_mac=state.src_mac,
                        dst_mac=state.dst_mac,
                    )
                    state.start_time = state.last_seen
                    state.last_seen = state.last_seen
                    state.last_flushed = now
                    state.packet_count = 0
                    state.byte_count = 0

        # Emit summaries outside the lock
        for collection in (flushed, expired):
            for key, state in collection.items():
                summary = self._build_summary(key, state)
                try:
                    self.on_flow_expired(summary)
                except Exception:
                    continue

    def _build_summary(self, key: FlowKey, state: FlowState) -> FlowSummary:
        src_ip, dst_ip, sport, dport, proto = key
        start_dt = datetime.fromtimestamp(state.start_time, tz=timezone.utc)
        last_dt = datetime.fromtimestamp(state.last_seen, tz=timezone.utc)

        return FlowSummary(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=proto,
            start_time=start_dt.isoformat(),
            last_seen=last_dt.isoformat(),
            packet_count=state.packet_count,
            byte_count=state.byte_count,
            duration=state.duration,
            average_packet_size=state.average_packet_size,
            domain=state.domain,
            sni=state.sni,
            src_mac=state.src_mac,
            dst_mac=state.dst_mac,
            agent_id=self.agent_id,
            organization_id=self.organization_id,
        )

    def _evict_oldest_locked(self) -> None:
        """
        Evict a small batch of the oldest flows to protect memory
        when the table grows beyond the configured max_flows.
        """
        if not self._flows:
            return

        # Evict ~5% oldest flows at a time.
        batch_size = max(1, len(self._flows) // 20)
        oldest = sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)[:batch_size]
        for key, _ in oldest:
            self._flows.pop(key, None)

