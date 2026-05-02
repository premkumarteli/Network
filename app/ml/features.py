from __future__ import annotations

from typing import Any


FEATURE_VERSION = "flow-v1"
FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "duration",
    "average_packet_size",
    "src_port",
    "dst_port",
)


def _numeric(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def extract_flow_features(flow: Any) -> list[float]:
    return [
        _numeric(getattr(flow, "packet_count", 0)),
        _numeric(getattr(flow, "byte_count", 0)),
        _numeric(getattr(flow, "duration", 0)),
        _numeric(getattr(flow, "average_packet_size", 0)),
        _numeric(getattr(flow, "src_port", 0)),
        _numeric(getattr(flow, "dst_port", 0)),
    ]


def feature_metadata() -> dict:
    return {
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
    }
