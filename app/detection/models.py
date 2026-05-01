from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionSignal:
    name: str
    score: float
    confidence: float = 1.0
