import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from sklearn.utils.validation import check_is_fitted
import joblib
import os

from .features import FEATURE_NAMES, FEATURE_VERSION

logger = logging.getLogger("netvisor.ml.model")

class NetVisorModel:
    def __init__(self, model_path="data/models/isolation_forest.pkl"):
        self.model_path = model_path
        self.feature_version = FEATURE_VERSION
        self.feature_names = list(FEATURE_NAMES)
        self.model = self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, dict) and "model" in loaded:
                    self.feature_version = loaded.get("feature_version") or FEATURE_VERSION
                    self.feature_names = list(loaded.get("feature_names") or FEATURE_NAMES)
                    return loaded["model"]
                return loaded
            except (OSError, ValueError, EOFError) as e:
                logger.warning(f"Failed to load model: {e}, using default")
        return IsolationForest(contamination=0.01, random_state=42)

    def fit(self, X):
        """Fit the model with features X."""
        self.model.fit(X)
        # Ensure directory exists before saving
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_version": self.feature_version,
                "feature_names": self.feature_names,
            },
            self.model_path,
        )
        logger.info(f"Model fitted and saved to {self.model_path}")

    def metadata(self) -> dict:
        return {
            "model_type": self.model.__class__.__name__,
            "feature_version": self.feature_version,
            "feature_names": list(self.feature_names),
            "feature_count": len(self.feature_names),
            "model_path": self.model_path,
        }

    def predict(self, features: list) -> float:
        try:
            # Check if model is fitted
            try:
                check_is_fitted(self.model)
            except Exception:
                # If not fitted, return a neutral score (0.0) without warning
                return 0.0

            X = np.array(features).reshape(1, -1)
            score = self.model.decision_function(X)[0]
            prob = 1.0 - (score + 0.5)
            return float(np.clip(prob, 0.0, 1.0))
        except (ValueError, TypeError) as e:
            logger.warning(f"Prediction failed: {e}")
            return 0.0

model = NetVisorModel()
