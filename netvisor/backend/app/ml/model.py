import numpy as np
import logging
from sklearn.ensemble import IsolationForest
import pickle
import os

logger = logging.getLogger("netvisor.ml.model")

class NetVisorModel:
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
        return IsolationForest(contamination=0.01, random_state=42)

    def predict(self, features: list) -> float:
        try:
            X = np.array(features).reshape(1, -1)
            score = self.model.decision_function(X)[0]
            prob = 1.0 - (score + 0.5)
            return float(np.clip(prob, 0.0, 1.0))
        except:
            return 0.0

model = NetVisorModel()
