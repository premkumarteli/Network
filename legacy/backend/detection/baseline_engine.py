import logging
import numpy as np
from typing import Dict

logger = logging.getLogger("netvisor.detection.baseline")

class BaselineEngine:
    def __init__(self):
        # In-memory storage for rolling stats (In production, load from DB)
        self.device_history: Dict[str, Dict] = {}

    def compute_score(self, src_ip, current_val, baseline_val, std_dev) -> float:
        """Computes a Z-score based deviation score (0-1)."""
        if std_dev <= 0:
            return 0.5 if current_val > baseline_val * 2 else 0.0
            
        z_score = (current_val - baseline_val) / std_dev
        
        if z_score > 3: return 1.0 # Critical deviation
        if z_score > 1.5: return 0.5 # Moderate deviation
        return 0.0

    def analyze(self, src_ip, connections_pm, unique_dst, avg_duration, baseline) -> float:
        """
        Computes normalized baseline_score (0-1).
        """
        if not baseline:
            return 0.0
            
        scores = []
        
        # 1. Connection Rate
        scores.append(self.compute_score(src_ip, connections_pm, baseline.get('avg_connections_per_min', 0), 10)) # Assuming fixed stddev for now
        
        # 2. Unique Destinations
        scores.append(self.compute_score(src_ip, unique_dst, baseline.get('avg_unique_destinations', 0), 5))
        
        # 3. Flow Duration
        scores.append(self.compute_score(src_ip, avg_duration, baseline.get('avg_flow_duration', 0), 30))
        
        return float(np.mean(scores))

baseline_engine = BaselineEngine()
