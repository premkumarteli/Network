from __future__ import annotations

from collections import defaultdict
import threading
from typing import Any


def _normalize_labels(labels: dict[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in labels.items()))


def _format_metric_key(name: str, labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return name
    rendered = ",".join(f'{key}="{value}"' for key, value in labels)
    return f"{name}{{{rendered}}}"


class MetricsService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], dict[str, float]] = {}

    def increment(self, name: str, amount: int = 1, **labels: Any) -> None:
        normalized_labels = _normalize_labels(labels)
        with self._lock:
            self._counters[(name, normalized_labels)] += int(amount)

    def set_gauge(self, name: str, value: float, **labels: Any) -> None:
        normalized_labels = _normalize_labels(labels)
        with self._lock:
            self._gauges[(name, normalized_labels)] = float(value)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        normalized_labels = _normalize_labels(labels)
        numeric = float(value)
        with self._lock:
            histogram = self._histograms.setdefault(
                (name, normalized_labels),
                {"count": 0.0, "sum": 0.0, "max": 0.0},
            )
            histogram["count"] += 1.0
            histogram["sum"] += numeric
            histogram["max"] = max(float(histogram.get("max") or 0.0), numeric)

    def snapshot(self, prefix: str | None = None) -> dict[str, dict[str, Any]]:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {key: dict(value) for key, value in self._histograms.items()}

        def include(name: str) -> bool:
            return not prefix or name.startswith(prefix)

        return {
            "counters": {
                _format_metric_key(name, labels): value
                for (name, labels), value in counters.items()
                if include(name)
            },
            "gauges": {
                _format_metric_key(name, labels): value
                for (name, labels), value in gauges.items()
                if include(name)
            },
            "histograms": {
                _format_metric_key(name, labels): value
                for (name, labels), value in histograms.items()
                if include(name)
            },
        }

    def prometheus_text(self, prefix: str | None = None) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {key: dict(value) for key, value in self._histograms.items()}

        def include(name: str) -> bool:
            return not prefix or name.startswith(prefix)

        def render(name: str, labels: tuple[tuple[str, str], ...], *, suffix: str | None = None) -> str:
            metric_name = f"{name}_{suffix}" if suffix else name
            if not labels:
                return metric_name
            rendered_labels = ",".join(f'{key}="{value}"' for key, value in labels)
            return f"{metric_name}{{{rendered_labels}}}"

        lines: list[str] = []

        for (name, labels), value in sorted(counters.items()):
            if include(name):
                lines.append(f"{render(name, labels)} {value}")
        for (name, labels), value in sorted(gauges.items()):
            if include(name):
                lines.append(f"{render(name, labels)} {value}")
        for (name, labels), value in sorted(histograms.items()):
            if not include(name):
                continue
            lines.append(f"{render(name, labels, suffix='count')} {int(value.get('count') or 0)}")
            lines.append(f"{render(name, labels, suffix='sum')} {float(value.get('sum') or 0.0)}")
            lines.append(f"{render(name, labels, suffix='max')} {float(value.get('max') or 0.0)}")

        return "\n".join(lines) + ("\n" if lines else "")


metrics_service = MetricsService()
