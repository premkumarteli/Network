import numpy as np
import os
from types import SimpleNamespace

import joblib

from app.ml.features import FEATURE_NAMES, FEATURE_VERSION, extract_flow_features, feature_metadata
from app.ml.model import NetVisorModel


def test_flow_feature_contract_is_versioned():
    flow = SimpleNamespace(
        packet_count=10,
        byte_count=2048,
        duration=2.5,
        average_packet_size=204.8,
        src_port=51515,
        dst_port=443,
    )

    assert extract_flow_features(flow) == [10.0, 2048.0, 2.5, 204.8, 51515.0, 443.0]
    assert feature_metadata() == {
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
    }


def test_unfitted_model_returns_zero():
    """Verify that an unfitted model returns 0.0 without errors."""
    # Use a temporary model path to avoid interference
    temp_model_path = "tmp/test_isolation_forest.pkl"
    if os.path.exists(temp_model_path):
        os.remove(temp_model_path)
    
    model = NetVisorModel(model_path=temp_model_path)
    features = [1, 2, 3, 4, 5, 6]
    
    # This should return 0.0 and NOT raise a 'NotFittedError' or log a warning
    score = model.predict(features)
    assert score == 0.0

def test_model_fitting_and_prediction():
    """Verify that fitting the model results in non-zero predictions."""
    temp_model_path = "tmp/test_isolation_forest_fitted.pkl"
    if os.path.exists(temp_model_path):
        os.remove(temp_model_path)
    
    model = NetVisorModel(model_path=temp_model_path)
    
    # Create some dummy data to fit
    X_train = np.random.rand(100, 6)
    model.fit(X_train)
    
    assert os.path.exists(temp_model_path)
    
    # Now predict should return a value between 0 and 1
    features = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
    score = model.predict(features)
    assert 0.0 <= score <= 1.0
    persisted = joblib.load(temp_model_path)
    assert persisted["feature_version"] == FEATURE_VERSION
    assert persisted["feature_names"] == list(FEATURE_NAMES)
    assert model.metadata()["feature_count"] == len(FEATURE_NAMES)
    
    # Cleanup
    if os.path.exists(temp_model_path):
        os.remove(temp_model_path)

