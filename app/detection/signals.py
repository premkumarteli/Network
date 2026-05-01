from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from ipaddress import ip_address, ip_network
from statistics import mean, pstdev
import math

from .models import DetectionSignal


class DetectionSignals:
    def __init__(self) -> None:
        self.port_attempts = defaultdict(deque)
        self.beacon_history = defaultdict(deque)
        self.byte_history = defaultdict(lambda: deque(maxlen=20))
        self.blacklisted_ip_ranges = (
            ip_network("45.2.3.0/24"),
            ip_network("103.1.2.0/24"),
            ip_network("198.51.100.0/24"),
            ip_network("203.0.113.0/24"),
        )
        self.blacklisted_domains = {
            "malware.test",
            "c2.netvisor.test",
            "botnet.invalid",
        }
        self.dns_subdomain_counts = defaultdict(lambda: defaultdict(set))
        self.failed_conn_attempts = defaultdict(deque)

    def _prune(self, bucket: deque, observed_at: datetime, window_seconds: int) -> None:
        while bucket:
            head = bucket[0]
            head_ts = head[0] if isinstance(head, tuple) else head
            if not isinstance(head_ts, datetime):
                break
            if (observed_at - head_ts).total_seconds() <= window_seconds:
                break
            bucket.popleft()

    def detect_blacklisted_destination(self, flow) -> DetectionSignal | None:
        dst_ip = getattr(flow, "dst_ip", "")
        domain = str(getattr(flow, "domain", "") or "").lower()
        try:
            dst_ip_obj = ip_address(dst_ip)
        except ValueError:
            dst_ip_obj = None

        if dst_ip_obj and any(dst_ip_obj in network for network in self.blacklisted_ip_ranges):
            return DetectionSignal("Malicious IP Communication", 1.0)

        if domain and any(domain == blocked or domain.endswith(f".{blocked}") for blocked in self.blacklisted_domains):
            return DetectionSignal("Malicious IP Communication", 1.0)

        return None

    def detect_port_scan(self, flow, observed_at: datetime) -> DetectionSignal | None:
        bucket = self.port_attempts[getattr(flow, "src_ip", "0.0.0.0")]
        bucket.append((observed_at, getattr(flow, "dst_port", 0)))
        self._prune(bucket, observed_at, 10)
        unique_ports = {port for _, port in bucket}
        if len(unique_ports) >= 10:
            return DetectionSignal("Port Scanning Detected", 1.0)
        return None

    def detect_beaconing(self, flow, observed_at: datetime) -> DetectionSignal | None:
        key = (
            getattr(flow, "src_ip", "0.0.0.0"),
            getattr(flow, "dst_ip", "0.0.0.0"),
            getattr(flow, "dst_port", 0),
        )
        bucket = self.beacon_history[key]
        bucket.append((observed_at, getattr(flow, "byte_count", 0)))
        self._prune(bucket, observed_at, 1800)
        if len(bucket) < 5:
            return None

        timestamps = [ts for ts, _ in bucket]
        intervals = [
            (timestamps[idx] - timestamps[idx - 1]).total_seconds()
            for idx in range(1, len(timestamps))
        ]
        avg_interval = mean(intervals)
        interval_stdev = pstdev(intervals) if len(intervals) > 1 else 0.0
        if 5 <= avg_interval <= 600 and interval_stdev <= max(1.0, avg_interval * 0.1):
            return DetectionSignal("Possible C2 Beaconing", 0.9, confidence=0.9)
        return None

    def detect_traffic_spike(self, flow, ml_score: float) -> DetectionSignal | None:
        src_ip = getattr(flow, "src_ip", "0.0.0.0")
        current_bytes = float(getattr(flow, "byte_count", 0) or 0)
        history = self.byte_history[src_ip]
        baseline_avg = mean(history) if history else 0.0
        history.append(current_bytes)

        if ml_score >= 0.8:
            return DetectionSignal("Anomalous Traffic Behavior", 0.8, confidence=0.7)
        if len(history) >= 5 and current_bytes >= max(75_000, baseline_avg * 4):
            return DetectionSignal("Anomalous Traffic Behavior", 0.7, confidence=0.6)
        return None

    def detect_vpn_proxy(self, flow, vpn_score: float) -> DetectionSignal | None:
        duration = float(getattr(flow, "duration", 0) or 0)
        average_packet_size = float(getattr(flow, "average_packet_size", 0) or 0)
        dst_port = int(getattr(flow, "dst_port", 0) or 0)
        if vpn_score >= 0.6:
            return DetectionSignal("Possible VPN/Proxy Usage", 0.7, confidence=0.8)
        if vpn_score >= 0.3:
            return DetectionSignal("Possible VPN/Proxy Usage", 0.6, confidence=0.6)
        if dst_port in {443, 500, 4500, 1194} and duration >= 90 and 150 <= average_packet_size <= 450:
            return DetectionSignal("Possible VPN/Proxy Usage", 0.55, confidence=0.5)
        return None

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = defaultdict(int)
        for char in text:
            counts[char] += 1
        entropy = 0.0
        length = len(text)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def detect_dns_tunneling(self, flow, observed_at: datetime) -> DetectionSignal | None:
        domain = str(getattr(flow, "domain", "") or "").lower()
        if not domain or domain.count(".") < 2:
            return None

        parts = domain.split(".")
        subdomain = parts[0]
        entropy = self._calculate_entropy(subdomain)
        if len(subdomain) > 15 and entropy > 3.8:
            return DetectionSignal("DNS Tunneling (High Entropy)", 0.85, confidence=0.8)

        parent_domain = ".".join(parts[-2:])
        src_ip = getattr(flow, "src_ip", "0.0.0.0")
        self.dns_subdomain_counts[src_ip][parent_domain].add(subdomain)
        if len(self.dns_subdomain_counts[src_ip][parent_domain]) > 50:
            return DetectionSignal("DNS Tunneling (Subdomain Bloom)", 0.8, confidence=0.7)

        return None

    def detect_brute_force(self, flow, observed_at: datetime) -> DetectionSignal | None:
        src_ip = getattr(flow, "src_ip", "0.0.0.0")
        dst_ip = getattr(flow, "dst_ip", "0.0.0.0")
        dst_port = int(getattr(flow, "dst_port", 0) or 0)
        byte_count = float(getattr(flow, "byte_count", 0) or 0)
        duration = float(getattr(flow, "duration", 0) or 0)

        if duration < 1.0 and byte_count < 500 and dst_port in {22, 3389, 445, 80, 443}:
            key = (src_ip, dst_ip, dst_port)
            bucket = self.failed_conn_attempts[key]
            bucket.append(observed_at)
            self._prune(bucket, observed_at, 60)
            if len(bucket) >= 15:
                return DetectionSignal("Potential Brute Force Attack", 0.9, confidence=0.85)
        return None

    def detect_data_exfiltration(self, flow, observed_at: datetime) -> DetectionSignal | None:
        uploaded_bytes = float(getattr(flow, "bytes_out", 0) or 0)
        if uploaded_bytes <= 0:
            internal_ip = getattr(flow, "internal_device_ip", None)
            external_ip = getattr(flow, "external_endpoint_ip", None)
            if internal_ip and external_ip:
                uploaded_bytes = float(getattr(flow, "byte_count", 0) or 0)
        if uploaded_bytes > 5_000_000:
            return DetectionSignal("Suspected Data Exfiltration", 0.75, confidence=0.7)
        return None

    def collect(self, flow, observed_at: datetime, ml_score: float, vpn_score: float) -> list[DetectionSignal]:
        signals = []
        for detector in (
            self.detect_blacklisted_destination(flow),
            self.detect_port_scan(flow, observed_at),
            self.detect_beaconing(flow, observed_at),
            self.detect_traffic_spike(flow, ml_score),
            self.detect_vpn_proxy(flow, vpn_score),
            self.detect_dns_tunneling(flow, observed_at),
            self.detect_brute_force(flow, observed_at),
            self.detect_data_exfiltration(flow, observed_at),
        ):
            if detector:
                signals.append(detector)
        return signals
