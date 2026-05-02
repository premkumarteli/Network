from ..ml.model import model
from ..ml.features import extract_flow_features, feature_metadata

class MLService:
    def predict_anomaly(self, flow) -> float:
        return model.predict(extract_flow_features(flow))

    def feature_metadata(self) -> dict:
        return feature_metadata()

ml_service = MLService()
