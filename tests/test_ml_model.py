import pytest
import numpy as np
import os
import shutil
from app.ml.model import NetVisorModel

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
    
    # Cleanup
    if os.path.exists(temp_model_path):
        os.remove(temp_model_path)

