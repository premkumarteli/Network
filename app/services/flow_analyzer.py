import logging

logger = logging.getLogger("netvisor.services.flow_analyzer")

class FlowAnalyzer:
    def __init__(self):
        self.suspicious_ports = {4444, 6667, 3389, 22, 23, 445, 135, 139, 5900, 8080}

    def analyze(self, flow) -> float:
        score = 0.0
        dst_port = getattr(flow, "dst_port", 0)
        byte_count = getattr(flow, "byte_count", 0)
        duration = getattr(flow, "duration", 0)

        if dst_port in self.suspicious_ports:
            score += 0.3
            
        if byte_count > 100_000_000 and duration < 10:
            score += 0.2
            
        return min(1.0, score)

flow_analyzer = FlowAnalyzer()
