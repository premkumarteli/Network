from ..ml.model import model

class MLService:
    def predict_anomaly(self, flow) -> float:
        features = [
            getattr(flow, "packet_count", 0),
            getattr(flow, "byte_count", 0),
            getattr(flow, "duration", 0),
            getattr(flow, "average_packet_size", 0),
            getattr(flow, "src_port", 0),
            getattr(flow, "dst_port", 0)
        ]
        return model.predict(features)

ml_service = MLService()
