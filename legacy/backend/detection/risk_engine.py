from .flow_analyzer import flow_analyzer
from .dns_analyzer import dns_analyzer
from .baseline_engine import baseline_engine
from .ml_engine import ml_engine
from .vpn_detector import VPNDetector
import logging

logger = logging.getLogger("netvisor.detection.risk")

class RiskEngine:
    def __init__(self):
        self.vpn_detector = VPNDetector()

    def evaluate_flow(self, flow, baseline=None) -> dict:
        """
        Phase 2: Final risk assessment based on the hybrid formula.
        final_risk = (flow * 0.25) + (dns * 0.20) + (baseline * 0.20) + (ml * 0.25) + (vpn * 0.10)
        """
        # 1. Component Scores
        flow_score = flow_analyzer.analyze(flow)
        
        dns_score = 0.0
        # If it's a DNS flow or we have domain data
        if hasattr(flow, 'domain') and flow.domain:
            dns_score = dns_analyzer.analyze(flow.domain)
        elif flow.dst_port == 53:
            dns_score = 0.3 # generic flag for DNS traffic if no domain captured
            
        # Baseline analysis (assuming connection rate / unique destinations provided in 'flow' object for context)
        # In a real impl, these are pulled from a windowing service
        conn_rate = getattr(flow, 'conn_rate', 0)
        unique_dst = getattr(flow, 'unique_dst', 0)
        base_score = baseline_engine.analyze(flow.src_ip, conn_rate, unique_dst, flow.duration, baseline)
        
        # ML Inference
        # Features: [packet_count, byte_count, duration, avg_packet_size, src_port, dst_port]
        features = [flow.packet_count, flow.byte_count, flow.duration, flow.average_packet_size, flow.src_port, flow.dst_port]
        ml_score = ml_engine.predict(features)
        
        # VPN Detection
        vpn_score, _ = self.vpn_detector.analyze_vpn(flow.src_ip, flow.dst_ip, flow.dst_port)
        vpn_score /= 40.0 # Normalize existing vpn_detector score (max ~40)
        
        # 2. Weighted Formula
        final_risk = (
            (flow_score * 0.25) +
            (dns_score * 0.20) +
            (base_score * 0.20) +
            (ml_score * 0.25) +
            (vpn_score * 0.10)
        )
        
        # Normalize to 0-100
        final_score = min(100, int(final_risk * 100))
        
        # Severity Assignment
        severity = "LOW"
        if final_score >= 80: severity = "CRITICAL"
        elif final_score >= 60: severity = "HIGH"
        elif final_score >= 30: severity = "MEDIUM"
        
        breakdown = {
            "flow_score": round(flow_score, 2),
            "dns_score": round(dns_score, 2),
            "baseline_score": round(base_score, 2),
            "ml_score": round(ml_score, 2),
            "vpn_score": round(vpn_score, 2)
        }
        
        return {
            "score": final_score,
            "severity": severity,
            "breakdown": breakdown,
            "reasons": self._generate_reasons(breakdown, severity)
        }

    def _generate_reasons(self, breakdown, severity):
        reasons = []
        if breakdown["flow_score"] > 0.5: reasons.append("Anomalous port/connection pattern")
        if breakdown["dns_score"] > 0.5: reasons.append("Suspicious DNS/DGA activity")
        if breakdown["ml_score"] > 0.7: reasons.append("ML Anomaly Detected")
        if breakdown["vpn_score"] > 0.5: reasons.append("VPN Tunneling signature")
        if breakdown["baseline_score"] > 0.5: reasons.append("Behavioral deviation from baseline")
        return reasons

risk_engine = RiskEngine()
