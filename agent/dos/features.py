"""
Shared DoS feature schema.

One row = one fixed-length metrics window observed at a protected service.
The same raw metrics are produced by the synthetic dataset generator and (later)
by the live metrics collector, and the same baseline-relative features are
computed by `add_baseline_features` in both places so training and inference match.
"""

from typing import Dict, List, Optional, Sequence

import math
import statistics

WINDOW_SECONDS = 5
BASELINE_WINDOWS = 12  # rolling baseline = previous 60s of windows

# Raw metrics measured per window at the service / host
RAW_FEATURES: List[str] = [
    "request_rate",            # completed + failed requests per second
    "active_connections",      # mean concurrently open client connections
    "new_connection_rate",     # new TCP connections accepted per second
    "failed_request_ratio",    # (5xx + timeouts + resets) / requests, 0..1
    "latency_p50_ms",          # median response latency (NaN when no requests)
    "latency_p95_ms",          # 95th percentile latency (NaN when no requests)
    "cpu_percent",             # host/service CPU utilisation, 0..100 (NaN on collection gap)
    "memory_percent",          # host/service memory utilisation, 0..100 (NaN on collection gap)
    "unique_clients",          # distinct client identifiers seen in window
    "top_client_share",        # share of requests from the busiest client, 0..1
    "slow_connection_ratio",   # open connections with no completed request in >10s / active, 0..1
]

# Derived relative to the rolling baseline of preceding windows in the same session
DERIVED_FEATURES: List[str] = [
    "request_rate_ratio_to_baseline",
    "latency_p95_ratio_to_baseline",
    "connections_ratio_to_baseline",
]

FEATURE_NAMES: List[str] = RAW_FEATURES + DERIVED_FEATURES

LABEL_COLUMN = "label"
LABEL_BENIGN = "benign"
LABEL_DOS = "dos"


def _baseline(values: Sequence[float]) -> Optional[float]:
    clean = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    return statistics.median(clean) if clean else None


def _ratio(current: Optional[float], baseline: Optional[float], floor: float) -> float:
    if current is None or (isinstance(current, float) and math.isnan(current)):
        return float("nan")
    if baseline is None:
        return 1.0
    return float(current) / max(float(baseline), floor)


def add_baseline_features(windows: List[Dict[str, float]]) -> List[Dict[str, float]]:
    """Adds DERIVED_FEATURES to an ordered list of windows from ONE session/service.
    Uses only preceding windows (no look-ahead), exactly as a live detector can."""
    out = []
    for i, w in enumerate(windows):
        prev = windows[max(0, i - BASELINE_WINDOWS):i]
        row = dict(w)
        row["request_rate_ratio_to_baseline"] = _ratio(
            w["request_rate"], _baseline([p["request_rate"] for p in prev]), floor=1.0)
        row["latency_p95_ratio_to_baseline"] = _ratio(
            w["latency_p95_ms"], _baseline([p["latency_p95_ms"] for p in prev]), floor=5.0)
        row["connections_ratio_to_baseline"] = _ratio(
            w["active_connections"], _baseline([p["active_connections"] for p in prev]), floor=1.0)
        out.append(row)
    return out
