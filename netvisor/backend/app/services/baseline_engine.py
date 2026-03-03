import numpy as np
import logging

logger = logging.getLogger("netvisor.services.baseline")

class BaselineEngine:
    def compute_score(self, current_val, baseline_val, std_dev) -> float:
        if std_dev <= 0:
            return 0.5 if current_val > baseline_val * 2 else 0.0
        z_score = (current_val - baseline_val) / std_dev
        if z_score > 3: return 1.0
        if z_score > 1.5: return 0.5
        return 0.0

    def analyze(self, connections_pm, unique_dst, avg_duration, baseline) -> float:
        if not baseline:
            return 0.0
        scores = []
        scores.append(self.compute_score(connections_pm, baseline.get('avg_connections_per_min', 0), 10))
        scores.append(self.compute_score(unique_dst, baseline.get('avg_unique_destinations', 0), 5))
        scores.append(self.compute_score(avg_duration, baseline.get('avg_flow_duration', 0), 30))
        return float(np.mean(scores))

baseline_engine = BaselineEngine()
