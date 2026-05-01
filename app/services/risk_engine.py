from .flow_analyzer import flow_analyzer
from .dns_analyzer import dns_analyzer
from .baseline_engine import baseline_engine
from .ml_service import ml_service
from .vpn_detector import vpn_detector
from app.detection.signals import DetectionSignals
from app.detection.scoring import (
    compute_base_score,
    compute_detection_score,
    compute_final_score,
    resolve_severity,
)
from app.detection.explanation import build_reasons
from collections import defaultdict, deque
from datetime import datetime
import logging

logger = logging.getLogger("netvisor.services.risk_engine")

class RiskEngine:
    def __init__(self):
        self.signals = DetectionSignals()

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

    def evaluate_flow(self, flow, baseline=None) -> dict:
        if not getattr(flow, "src_ip", None) or not getattr(flow, "dst_ip", None):
            logger.debug("Skipping risk evaluation for flow missing src/dst IP.")
            return {
                "score": 0,
                "severity": "LOW",
                "breakdown": {
                    "flow_score": 0.0,
                    "dns_score": 0.0,
                    "baseline_score": 0.0,
                    "ml_score": 0.0,
                    "vpn_score": 0.0,
                    "detection_score": 0.0,
                    "signals": [],
                },
                "reasons": [],
                "signals": [],
                "primary_detection": None,
            }
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
        host_hint = getattr(flow, 'sni', None) or getattr(flow, 'domain', None)
        vpn_raw_score, _ = vpn_detector.analyze_vpn(src_ip, dst_ip, dst_port, host_hint)
        vpn_score = min(1.0, vpn_raw_score / 40.0)

        detections = self.signals.collect(flow, observed_at, ml_score, vpn_score)
        detection_score = compute_detection_score(detections)
        base_risk = compute_base_score(
            flow_score=flow_score,
            dns_score=dns_score,
            baseline_score=base_score,
            ml_score=ml_score,
            vpn_score=vpn_score,
        )
        final_score = compute_final_score(base_risk, detection_score, detections)
        severity = resolve_severity(final_score)
        
        breakdown = {
            "flow_score": round(flow_score, 2),
            "dns_score": round(dns_score, 2),
            "baseline_score": round(base_score, 2),
            "ml_score": round(ml_score, 2),
            "vpn_score": round(vpn_score, 2),
            "detection_score": round(detection_score, 2),
            "signals": [signal.name for signal in detections],
        }
        primary_detection = max(detections, key=lambda signal: signal.score).name if detections else None
        
        return {
            "score": final_score,
            "severity": severity,
            "breakdown": breakdown,
            "reasons": build_reasons(breakdown),
            "signals": [signal.name for signal in detections],
            "primary_detection": primary_detection,
        }

risk_engine = RiskEngine()
