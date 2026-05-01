import numpy as np
import logging

logger = logging.getLogger("netvisor.services.baseline")

class BaselineEngine:
    def _dynamic_std_dev(self, baseline_val: float, std_dev: float | None, minimum: float) -> float:
        if std_dev and std_dev > 0:
            return float(std_dev)
        return max(float(baseline_val or 0) * 0.35, minimum)

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
        conn_avg = baseline.get('avg_connections_per_min', 0)
        conn_std = self._dynamic_std_dev(conn_avg, baseline.get('std_dev_connections'), 5)
        scores.append(self.compute_score(connections_pm, conn_avg, conn_std))

        unique_avg = baseline.get('avg_unique_destinations', 0)
        unique_std = self._dynamic_std_dev(unique_avg, baseline.get('std_dev_unique_destinations'), 2)
        scores.append(self.compute_score(unique_dst, unique_avg, unique_std))

        duration_avg = baseline.get('avg_flow_duration', 0)
        duration_std = self._dynamic_std_dev(duration_avg, baseline.get('std_dev_flow_duration'), 10)
        scores.append(self.compute_score(avg_duration, duration_avg, duration_std))
        return float(np.mean(scores))

baseline_engine = BaselineEngine()
