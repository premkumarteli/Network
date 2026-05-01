from app.services.baseline_engine import baseline_engine


def test_dynamic_variance_increases_score_when_baseline_is_small():
    baseline = {
        "avg_connections_per_min": 5,
        "avg_unique_destinations": 2,
        "avg_flow_duration": 10,
        "std_dev_connections": 0,
    }
    score = baseline_engine.analyze(20, 10, 60, baseline)
    assert score > 0.0
