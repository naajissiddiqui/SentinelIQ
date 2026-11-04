"""
The ONE feature schema shared by training and inference.

Every consumer — the extractor that writes window rows, the dataset builder,
the trainer and the replay scorer — imports the names and order from here, so a
model can never be fed columns in a different order or with a different
meaning than it was trained on. `schema_fingerprint()` is stored with every
model and checked before scoring.

A window row has two disjoint parts:
  - KEY_COLUMNS identify the row (which destination, which 5-second slot).
    They are used for grouping, joining labels and display. NEVER as features.
  - FEATURE_NAMES are the only values a model may see, in exactly this order.

FORBIDDEN_FEATURES lists what must never become a feature: addresses, port
values, timestamps, flow identifiers, dataset-specific header fields that are
known shortcuts in the CIC datasets (TTL, IP ID, initial TCP window), and
labels. `assert_feature_names_safe()` enforces it.
"""

import hashlib
import math
from typing import Dict, List, Mapping, Sequence

SCHEMA_VERSION = "dos-window-v1"

WINDOW_SECONDS = 5
WINDOW_NS = WINDOW_SECONDS * 1_000_000_000

# Baseline ratios compare a window with the previous BASELINE_WINDOWS slots of
# the same destination (60 s). Missing slots count as zero traffic.
BASELINE_WINDOWS = 12

# Columns that identify a window row. Not features.
KEY_COLUMNS: List[str] = [
    "schema_version",
    "window_start_ns",
    "window_start_utc",
    "dst_ip",
]

FEATURE_NAMES: List[str] = [
    # Volume. "in" = packets whose destination is this host, "out" = packets it sent.
    "in_packets",
    "in_bytes",
    "in_pkts_per_s",
    "in_bytes_per_s",
    "out_packets",
    "out_bytes",
    "out_in_packet_ratio",
    # Inbound packet sizes (IP total length).
    "in_len_mean",
    "in_len_std",
    "in_len_min",
    "in_len_max",
    "in_len_p50",
    "in_len_p95",
    # Inbound inter-arrival times, in arrival order.
    "in_iat_mean_ms",
    "in_iat_std_ms",
    "in_iat_min_ms",
    "in_iat_max_ms",
    "in_iat_cv",
    # Inbound protocol mix.
    "in_tcp_share",
    "in_udp_share",
    "in_icmp_share",
    "in_other_share",
    "in_fragment_share",
    # Inbound TCP flags (NaN when the window has no inbound TCP).
    "tcp_syn_only_ratio",
    "tcp_synack_reply_ratio",
    "tcp_rst_ratio",
    "tcp_fin_ratio",
    "tcp_psh_ratio",
    "tcp_ack_only_ratio",
    # Source diversity. Port COUNTS only, never port values.
    "unique_src",
    "unique_src_prefix",
    "src_entropy_norm",
    "top_src_share",
    "unique_src_ports",
    "unique_dst_ports",
    # Flows seen inbound to this host within the window.
    "flows_active",
    "flows_new",
    "new_flows_per_s",
    "pkts_per_flow_mean",
    "pkts_per_flow_std",
    "pkts_per_flow_max",
    "bytes_per_flow_mean",
    "single_packet_flow_share",
    "unanswered_flow_share",
    # Against the previous BASELINE_WINDOWS slots (NaN with no history).
    "in_pps_ratio_baseline",
    "new_flow_rate_ratio_baseline",
    "unique_src_ratio_baseline",
]

# Completed-flow records (for evidence and a later flow-level ablation).
FLOW_KEY_COLUMNS: List[str] = [
    "schema_version",
    "protocol",
    "initiator_ip",
    "initiator_port",
    "responder_ip",
    "responder_port",
    "first_ts_ns",
    "last_ts_ns",
    "end_reason",
    "continued",
    "start_observed",
]

FLOW_FEATURE_NAMES: List[str] = [
    "duration_ms",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_len_mean",
    "fwd_len_std",
    "fwd_len_min",
    "fwd_len_max",
    "bwd_len_mean",
    "bwd_len_std",
    "bwd_len_min",
    "bwd_len_max",
    "pkts_per_s",
    "bytes_per_s",
    "iat_mean_ms",
    "iat_std_ms",
    "iat_min_ms",
    "iat_max_ms",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "syn_count",
    "synack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "ack_count",
    "fragment_count",
]

# Never allowed as a model input. Checked by name; extend when a new
# identifying or dataset-specific field is extracted anywhere.
FORBIDDEN_FEATURES = frozenset(
    {
        "src_ip",
        "dst_ip",
        "ip",
        "initiator_ip",
        "responder_ip",
        "src_port",
        "dst_port",
        "port",
        "initiator_port",
        "responder_port",
        "flow_id",
        "flow_key",
        "timestamp",
        "ts",
        "first_ts_ns",
        "last_ts_ns",
        "window_start_ns",
        "window_start_utc",
        "window_end_ns",
        "ttl",
        "hop_limit",
        "ip_id",
        "init_win_bytes",
        "tcp_window",
        "mac",
        "src_mac",
        "dst_mac",
        "payload",
        "label",
        "attack_family",
        "ground_truth",
        "schema_version",
        "end_reason",
        "continued",
        "start_observed",
        "protocol",
    }
)


def assert_feature_names_safe(names: Sequence[str]) -> None:
    """Raise if any feature name is forbidden, duplicated, or also a key column."""
    seen = set()
    for name in names:
        if name in FORBIDDEN_FEATURES:
            raise ValueError(f"forbidden feature: {name}")
        if name in KEY_COLUMNS or name in FLOW_KEY_COLUMNS:
            raise ValueError(f"key column used as a feature: {name}")
        if name in seen:
            raise ValueError(f"duplicate feature: {name}")
        seen.add(name)


def schema_fingerprint() -> str:
    """SHA-256 over everything a model depends on: version, window and order."""
    text = "\n".join(
        [
            SCHEMA_VERSION,
            f"window_seconds={WINDOW_SECONDS}",
            f"baseline_windows={BASELINE_WINDOWS}",
            "features:" + ",".join(FEATURE_NAMES),
            "flow_features:" + ",".join(FLOW_FEATURE_NAMES),
        ]
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def feature_vector(row: Mapping[str, float]) -> List[float]:
    """The model input for one row, in schema order. Raises on a missing feature."""
    missing = [n for n in FEATURE_NAMES if n not in row]
    if missing:
        raise KeyError(f"row is missing features: {missing}")
    return [float(row[n]) for n in FEATURE_NAMES]


def format_value(value) -> str:
    """Deterministic text form for CSV output (repr of floats, 'nan' for NaN)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float):
        if math.isnan(value):
            return "nan"
        return repr(value)
    return str(value)


def empty_feature_row() -> Dict[str, float]:
    return {name: math.nan for name in FEATURE_NAMES}


assert_feature_names_safe(FEATURE_NAMES)
assert_feature_names_safe(FLOW_FEATURE_NAMES)
