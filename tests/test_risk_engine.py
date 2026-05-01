from types import SimpleNamespace

from app.services.risk_engine import RiskEngine


def make_flow(**overrides):
    base = {
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "domain": None,
        "packet_count": 20,
        "byte_count": 5000,
        "duration": 3.0,
        "average_packet_size": 250.0,
        "agent_id": "agent-1",
        "organization_id": "org-1",
        "start_time": "2026-03-18 10:00:00",
        "last_seen": "2026-03-18 10:00:00",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_blacklisted_ip_detection_is_critical():
    engine = RiskEngine()
    report = engine.evaluate_flow(make_flow(dst_ip="203.0.113.10"))
    assert report["severity"] == "CRITICAL"
    assert "Malicious IP Communication" in report["reasons"]


def test_port_scan_detection_becomes_high_risk():
    engine = RiskEngine()
    report = None
    for port in range(20, 30):
        report = engine.evaluate_flow(
            make_flow(
                dst_port=port,
                last_seen=f"2026-03-18 10:00:0{port - 20}",
                duration=0.5,
            )
        )
    assert report is not None
    assert report["severity"] in {"HIGH", "CRITICAL"}
    assert "Port Scanning Detected" in report["reasons"]


def test_beaconing_detection_is_explicit():
    engine = RiskEngine()
    report = None
    for stamp in (
        "2026-03-18 10:02:00",
        "2026-03-18 10:02:30",
        "2026-03-18 10:03:00",
        "2026-03-18 10:03:30",
        "2026-03-18 10:04:00",
    ):
        report = engine.evaluate_flow(
            make_flow(
                dst_ip="198.18.0.10",
                dst_port=8080,
                byte_count=2400,
                packet_count=12,
                last_seen=stamp,
            )
        )
    assert report is not None
    assert "Possible C2 Beaconing" in report["reasons"]


def test_brute_force_detection_handles_timestamp_only_bucket_entries():
    engine = RiskEngine()
    report = None
    for second in range(15):
        report = engine.evaluate_flow(
            make_flow(
                dst_ip="10.0.0.20",
                dst_port=22,
                byte_count=120,
                duration=0.2,
                last_seen=f"2026-03-18 10:05:{second:02d}",
            )
        )

    assert report is not None
    assert "Potential Brute Force Attack" in report["reasons"]
    assert report["severity"] in {"HIGH", "CRITICAL"}

