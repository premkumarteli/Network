import numpy as np
import logging
from sklearn.ensemble import IsolationForest
import pickle
import os

logger = logging.getLogger("netvisor.detection.ml")

class MLEngine:
    def __init__(self, model_path="data/models/isolation_forest.pkl"):
        self.model_path = model_path
        self.model = self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    return pickle.load(f)
            except:
                pass
        # Initialize fresh model if not found
        return IsolationForest(contamination=0.01, random_state=42)

    def predict(self, feature_vector: list) -> float:
        """
        Predict anomaly probability (0-1).
        Feature Vector: [packet_count, byte_count, duration, avg_packet_size, src_port, dst_port]
        """
        try:
            # Note: IsolationForest.decision_function returns values where lower is more abnormal
            # We normalize to 0-1 (higher is more abnormal)
            X = np.array(feature_vector).reshape(1, -1)
            score = self.model.decision_function(X)[0]
            # Map score [-0.5, 0.5] roughly to [1, 0]
            prob = 1.0 - (score + 0.5)
            return float(np.clip(prob, 0.0, 1.0))
        except:
            return 0.0

    def train_online(self, X_batch):
        """Placeholder for periodic retraining."""
        # IsolationForest doesn't support partial_fit well, so we'd normally retrain on a buffer
        pass

ml_engine = MLEngine()
