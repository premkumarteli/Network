from .flow_analyzer import flow_analyzer
from .dns_analyzer import dns_analyzer
from .baseline_engine import baseline_engine
from .ml_service import ml_service
from .vpn_detector import vpn_detector
from collections import defaultdict, deque
from datetime import datetime
from ipaddress import ip_address, ip_network
from statistics import mean, pstdev
import logging

logger = logging.getLogger("netvisor.services.risk_engine")

class RiskEngine:
    def __init__(self):
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

    def _parse_timestamp(self, raw_value):
        if isinstance(raw_value, datetime):
            return raw_value
        if not raw_value:
            return datetime.utcnow()
        try:
            return datetime.fromisoformat(str(raw_value).replace("Z", "+00:00"))
        except ValueError:
            try:
                return datetime.strptime(str(raw_value), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return datetime.utcnow()

    def _prune(self, bucket: deque, observed_at: datetime, window_seconds: int) -> None:
        while bucket and (observed_at - bucket[0][0]).total_seconds() > window_seconds:
            bucket.popleft()

    def _detect_port_scan(self, flow, observed_at: datetime):
        bucket = self.port_attempts[getattr(flow, "src_ip", "0.0.0.0")]
        bucket.append((observed_at, getattr(flow, "dst_port", 0)))
        self._prune(bucket, observed_at, 10)
        unique_ports = {port for _, port in bucket}
        if len(unique_ports) >= 10:
            return {"name": "Port Scanning Detected", "score": 1.0}
        return None

    def _detect_beaconing(self, flow, observed_at: datetime):
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
            return {"name": "Possible C2 Beaconing", "score": 0.9}
        return None

    def _detect_blacklisted_destination(self, flow):
        dst_ip = getattr(flow, "dst_ip", "")
        domain = str(getattr(flow, "domain", "") or "").lower()
        try:
            dst_ip_obj = ip_address(dst_ip)
        except ValueError:
            dst_ip_obj = None

        if dst_ip_obj and any(dst_ip_obj in network for network in self.blacklisted_ip_ranges):
            return {"name": "Malicious IP Communication", "score": 1.0}

        if domain and any(domain == blocked or domain.endswith(f".{blocked}") for blocked in self.blacklisted_domains):
            return {"name": "Malicious IP Communication", "score": 1.0}

        return None

    def _detect_traffic_spike(self, flow, ml_score: float):
        src_ip = getattr(flow, "src_ip", "0.0.0.0")
        current_bytes = float(getattr(flow, "byte_count", 0) or 0)
        history = self.byte_history[src_ip]
        baseline_avg = mean(history) if history else 0.0
        history.append(current_bytes)

        if ml_score >= 0.8:
            return {"name": "Anomalous Traffic Behavior", "score": 0.8}
        if len(history) >= 5 and current_bytes >= max(75_000, baseline_avg * 4):
            return {"name": "Anomalous Traffic Behavior", "score": 0.7}
        return None

    def _detect_vpn_proxy(self, flow, vpn_score: float):
        duration = float(getattr(flow, "duration", 0) or 0)
        average_packet_size = float(getattr(flow, "average_packet_size", 0) or 0)
        dst_port = int(getattr(flow, "dst_port", 0) or 0)
        if vpn_score >= 0.3:
            return {"name": "Possible VPN/Proxy Usage", "score": 0.65}
        if dst_port in {443, 500, 4500, 1194} and duration >= 90 and 150 <= average_packet_size <= 450:
            return {"name": "Possible VPN/Proxy Usage", "score": 0.55}
        return None

    def evaluate_flow(self, flow, baseline=None) -> dict:
        observed_at = self._parse_timestamp(getattr(flow, "last_seen", None))
        flow_score = flow_analyzer.analyze(flow)
        
        domain = getattr(flow, 'domain', None)
        dst_port = getattr(flow, 'dst_port', 0)
        
        dns_score = 0.0
        if domain:
            dns_score = dns_analyzer.analyze(domain)
        elif dst_port == 53:
            dns_score = 0.3
            
        conn_rate = getattr(flow, 'conn_rate', 0)
        unique_dst = getattr(flow, 'unique_dst', 0)
        duration = getattr(flow, 'duration', 0)
        base_score = baseline_engine.analyze(conn_rate, unique_dst, duration, baseline)
        
        ml_score = ml_service.predict_anomaly(flow)
        
        src_ip = getattr(flow, 'src_ip', '0.0.0.0')
        dst_ip = getattr(flow, 'dst_ip', '0.0.0.0')
        vpn_raw_score, _ = vpn_detector.analyze_vpn(src_ip, dst_ip, dst_port)
        vpn_score = vpn_raw_score / 40.0

        detections = []
        for detector in (
            self._detect_blacklisted_destination(flow),
            self._detect_port_scan(flow, observed_at),
            self._detect_beaconing(flow, observed_at),
            self._detect_traffic_spike(flow, ml_score),
            self._detect_vpn_proxy(flow, vpn_score),
        ):
            if detector:
                detections.append(detector)

        detection_score = max((signal["score"] for signal in detections), default=0.0)
        
        final_risk = (
            (flow_score * 0.25) +
            (dns_score * 0.20) +
            (base_score * 0.20) +
            (ml_score * 0.25) +
            (vpn_score * 0.10) +
            (detection_score * 0.35)
        )
        
        final_score = min(100, int(final_risk * 100))

        signal_floor_scores = {
            "Malicious IP Communication": 90,
            "Port Scanning Detected": 70,
            "Possible C2 Beaconing": 70,
            "Anomalous Traffic Behavior": 45,
            "Possible VPN/Proxy Usage": 35,
        }
        for signal in detections:
            final_score = max(final_score, signal_floor_scores.get(signal["name"], 0))
        
        severity = "LOW"
        if final_score >= 80: severity = "CRITICAL"
        elif final_score >= 60: severity = "HIGH"
        elif final_score >= 30: severity = "MEDIUM"
        
        breakdown = {
            "flow_score": round(flow_score, 2),
            "dns_score": round(dns_score, 2),
            "baseline_score": round(base_score, 2),
            "ml_score": round(ml_score, 2),
            "vpn_score": round(vpn_score, 2),
            "detection_score": round(detection_score, 2),
            "signals": [signal["name"] for signal in detections],
        }
        primary_detection = detections[0]["name"] if detections else None
        
        return {
            "score": final_score,
            "severity": severity,
            "breakdown": breakdown,
            "reasons": self._generate_reasons(breakdown),
            "signals": [signal["name"] for signal in detections],
            "primary_detection": primary_detection,
        }

    def _generate_reasons(self, breakdown):
        reasons = list(breakdown.get("signals", []))
        if breakdown["flow_score"] > 0.5 and "Port Scanning Detected" not in reasons:
            reasons.append("Anomalous port/connection pattern")
        if breakdown["dns_score"] > 0.5:
            reasons.append("Suspicious DNS/DGA activity")
        if breakdown["ml_score"] > 0.7 and "Anomalous Traffic Behavior" not in reasons:
            reasons.append("ML Anomaly Detected")
        if breakdown["vpn_score"] > 0.5 and "Possible VPN/Proxy Usage" not in reasons:
            reasons.append("VPN Tunneling signature")
        if breakdown["baseline_score"] > 0.5:
            reasons.append("Behavioral deviation from baseline")
        return list(dict.fromkeys(reasons))

risk_engine = RiskEngine()
