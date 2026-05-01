from app.services.vpn_detector import vpn_detector


def test_vpn_detector_scores_keyword_host():
    score, reason = vpn_detector.analyze_vpn("10.0.0.10", "8.8.8.8", 443, host="vpn.example.com")
    assert score > 0
    assert "keyword" in reason.lower()


def test_vpn_detector_scores_suspicious_port():
    score, reason = vpn_detector.analyze_vpn("10.0.0.10", "8.8.8.8", 1194)
    assert score > 0
    assert "port" in reason.lower()
