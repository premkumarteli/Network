from __future__ import annotations


def build_reasons(breakdown: dict) -> list[str]:
    reasons = list(breakdown.get("signals", []))
    if breakdown.get("flow_score", 0) > 0.5 and "Port Scanning Detected" not in reasons:
        reasons.append("Anomalous port/connection pattern")
    if breakdown.get("dns_score", 0) > 0.5:
        reasons.append("Suspicious DNS/DGA activity")
    if breakdown.get("ml_score", 0) > 0.7 and "Anomalous Traffic Behavior" not in reasons:
        reasons.append("ML Anomaly Detected")
    if breakdown.get("vpn_score", 0) > 0.5 and "Possible VPN/Proxy Usage" not in reasons:
        reasons.append("VPN Tunneling signature")
    if breakdown.get("baseline_score", 0) > 0.5:
        reasons.append("Behavioral deviation from baseline")
    return list(dict.fromkeys(reasons))
