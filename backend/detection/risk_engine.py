from .rule_engine import RuleEngine
from .anomaly_engine import AnomalyEngine
from .vpn_detector import VPNDetector
from services.ml.ml_engine import ml_engine

class RiskEngine:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.anomaly_engine = AnomalyEngine()
        self.vpn_detector = VPNDetector()

    def calculate_device_risk(self, domain, src_ip, dst_ip, port, rcode=0, baseline=None):
        """
        Aggregates all findings into a single risk report.
        Formula: risk = (anomaly_score * 0.5 + vpn_score * 0.3 + rule_score * 0.2)
        Wait, I'll stick to the one in the plan or a simplified aggregate.
        """
        # 1. Rule Engine (Lexical)
        rule_score, entropy = self.rule_engine.analyze(domain)
        
        # 2. Anomaly Engine (Behavioral)
        anomaly_score = self.anomaly_engine.analyze_behavior(src_ip, domain, rcode, baseline)
        
        # 3. VPN Detector
        vpn_score, vpn_reason = self.vpn_detector.analyze_vpn(src_ip, dst_ip, port)
        
        # 4. ML Engine
        ml_prob = ml_engine.predict_risk(domain)
        ml_score = 10 if ml_prob > 0.8 else (5 if ml_prob > 0.5 else 0)

        # FINAL AGGREGATION
        # We cap sub-scores or weight them
        # Total score 0-100
        total_score = (
            (anomaly_score * 4) + # max ~40
            (vpn_score * 2) +     # max ~40
            (rule_score * 3) +    # max ~21
            (ml_score * 2)        # max ~20
        )
        
        total_score = min(100, total_score)
        
        reasons = []
        if rule_score > 4: reasons.append("Suspicious Domain Structure (Lexical)")
        if anomaly_score > 4: reasons.append("Anomalous Query Rate/Pattern")
        if vpn_score > 0: reasons.append(vpn_reason or "VPN Tunneling pattern")
        if ml_score > 5: reasons.append("ML Classifier: Malicious Domain")
        
        severity = "LOW"
        if total_score > 70: severity = "HIGH"
        elif total_score > 30: severity = "MEDIUM"
        
        return {
            "score": total_score,
            "severity": severity,
            "reasons": reasons,
            "entropy": entropy,
            "ml_prob": ml_prob
        }

# Singleton
risk_engine = RiskEngine()
