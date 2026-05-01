from __future__ import annotations

from typing import Iterable

from .models import DetectionSignal


def compute_detection_score(signals: Iterable[DetectionSignal]) -> float:
    max_signal = max((signal.score for signal in signals), default=0.0)
    return float(max_signal)


def compute_base_score(*, flow_score: float, dns_score: float, baseline_score: float, ml_score: float, vpn_score: float) -> float:
    return (
        (flow_score * 0.25)
        + (dns_score * 0.20)
        + (baseline_score * 0.20)
        + (ml_score * 0.25)
        + (vpn_score * 0.10)
    )


def compute_final_score(base_score: float, detection_score: float, signals: Iterable[DetectionSignal]) -> int:
    final_risk = max(base_score, detection_score)
    final_score = min(100, int(final_risk * 100))

    signal_floor_scores = {
        "Malicious IP Communication": 90,
        "Port Scanning Detected": 70,
        "Possible C2 Beaconing": 70,
        "Anomalous Traffic Behavior": 45,
        "Possible VPN/Proxy Usage": 35,
        "DNS Tunneling (High Entropy)": 85,
        "DNS Tunneling (Subdomain Bloom)": 80,
        "Potential Brute Force Attack": 85,
        "Suspected Data Exfiltration": 65,
    }
    for signal in signals:
        final_score = max(final_score, signal_floor_scores.get(signal.name, 0))

    return final_score


def resolve_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
