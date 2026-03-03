from .flow_analyzer import flow_analyzer
from .dns_analyzer import dns_analyzer
from .baseline_engine import baseline_engine
from .ml_service import ml_service
from .vpn_detector import vpn_detector
import logging

logger = logging.getLogger("netvisor.services.risk_engine")

class RiskEngine:
    def evaluate_flow(self, flow, baseline=None) -> dict:
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
        
        final_risk = (
            (flow_score * 0.25) +
            (dns_score * 0.20) +
            (base_score * 0.20) +
            (ml_score * 0.25) +
            (vpn_score * 0.10)
        )
        
        final_score = min(100, int(final_risk * 100))
        
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
            "reasons": self._generate_reasons(breakdown)
        }

    def _generate_reasons(self, breakdown):
        reasons = []
        if breakdown["flow_score"] > 0.5: reasons.append("Anomalous port/connection pattern")
        if breakdown["dns_score"] > 0.5: reasons.append("Suspicious DNS/DGA activity")
        if breakdown["ml_score"] > 0.7: reasons.append("ML Anomaly Detected")
        if breakdown["vpn_score"] > 0.5: reasons.append("VPN Tunneling signature")
        if breakdown["baseline_score"] > 0.5: reasons.append("Behavioral deviation from baseline")
        return reasons

risk_engine = RiskEngine()
