import logging

logger = logging.getLogger("netvisor.detection.flow")

class FlowAnalyzer:
    def __init__(self):
        self.suspicious_ports = {4444, 6667, 3389, 22, 23, 445, 135, 139, 5900, 8080}
        self.port_scan_threshold = 20 # Unique ports per minute

    def analyze(self, flow) -> float:
        """
        Returns a normalized flow_score (0-1).
        """
        score = 0.0
        
        # 1. Suspicious Port Check
        if flow.dst_port in self.suspicious_ports:
            score += 0.3
            
        # 2. Port Scanning Heuristic (Requires state)
        # For a single flow, we can't detect scanning easily without historical context
        # but we can flag abnormal connection characteristics
        
        # 3. Size/Duration Anomalies
        if flow.byte_count > 100_000_000 and flow.duration < 10:
            score += 0.2 # Potential exfiltration burst
            
        return min(1.0, score)

flow_analyzer = FlowAnalyzer()
