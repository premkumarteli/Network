from app.services.metrics_service import MetricsService


def test_metrics_service_tracks_counters_gauges_and_histograms():
    service = MetricsService()

    service.increment("agent_auth_failures_total", reason="replay")
    service.increment("agent_auth_failures_total", reason="replay")
    service.set_gauge("flow_queue_depth", 12)
    service.observe("flow_persist_duration_ms", 5.5)
    service.observe("flow_persist_duration_ms", 7.0)

    snapshot = service.snapshot()

    assert snapshot["counters"]['agent_auth_failures_total{reason="replay"}'] == 2
    assert snapshot["gauges"]["flow_queue_depth"] == 12.0
    histogram = snapshot["histograms"]["flow_persist_duration_ms"]
    assert histogram["count"] == 2.0
    assert histogram["sum"] == 12.5
    assert histogram["max"] == 7.0
