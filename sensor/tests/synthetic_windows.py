"""
SYNTHETIC window fixtures for testing the ML software. NOT TRAINING DATA.

Writes directories shaped like extraction outputs (windows.csv + stats.json)
whose rows are generated from simple rules, plus label rules that are
"verified" only in the sense of being a unit-test fixture. The rules' dataset
name is "SYNTHETIC-FIXTURE", so every model trained on them is stamped
SYNTHETIC_TEST_ONLY and can never be presented as a detector.

Generated behaviour (chosen to exercise known risks, not to imitate CIC):
  - benign hosts with low traffic and occasional legitimate bursts (high
    packet rate, few flows, answered);
  - a victim with sustained floods of two families (UDP-like and SYN-like):
    many new unanswered flows, many destination ports. Baseline ratios are
    computed from the generated history exactly as the extractor does, so
    they spike at onset and fall back toward 1 during the flood.
"""

import hashlib
import json
import math
import os
import random
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from netsensor.schema import (
    BASELINE_WINDOWS, FEATURE_NAMES, KEY_COLUMNS, SCHEMA_VERSION, WINDOW_NS, format_value, schema_fingerprint,
)

VICTIM = "198.51.100.4"
BENIGN_HOSTS = [f"198.51.100.{i}" for i in range(10, 18)]
SLOT0 = 340_000_000  # 5 s slots since the epoch (2023-11-14)


def _median(values):
    v = sorted(values)
    m = len(v) // 2
    return v[m] if len(v) % 2 else (v[m - 1] + v[m]) / 2


def _row(slot: int, host: str, kind: str, rng: random.Random, history: deque) -> Dict[str, object]:
    if kind == "flood-udp" or kind == "flood-syn":
        pps = rng.uniform(8000, 30000)
        flows_new = pps * 5 * rng.uniform(0.4, 0.6)
        unanswered, dst_ports, out_ratio = rng.uniform(0.97, 1.0), rng.uniform(5000, 30000), rng.uniform(0, 0.01)
        tcp = 1.0 if kind == "flood-syn" else 0.0
        length = 60.0 if tcp else rng.uniform(200, 300)
        unique_src = rng.choice([1, 1, 2])
    elif kind == "burst":
        pps = rng.uniform(1500, 6000)
        flows_new = rng.uniform(0, 3)
        unanswered, dst_ports, out_ratio = 0.0, rng.uniform(1, 3), rng.uniform(0.3, 0.6)
        tcp, length, unique_src = 1.0, rng.uniform(1200, 1500), 1
    else:
        pps = rng.uniform(0.2, 30)
        flows_new = rng.uniform(0, 6)
        unanswered, dst_ports, out_ratio = rng.uniform(0, 0.4), rng.uniform(1, 12), rng.uniform(0.5, 1.5)
        tcp, length, unique_src = rng.choice([0.0, 0.6, 1.0]), rng.uniform(60, 900), rng.choice([1, 1, 2, 3])
    packets = max(1, round(pps * 5))
    pps = packets / 5
    flows_new = min(float(round(flows_new)), float(packets))
    flows_active = max(1.0, flows_new)
    tcp_present = tcp > 0
    recent = [h for h in history if slot - BASELINE_WINDOWS <= h[0] < slot]
    pad = BASELINE_WINDOWS - len(recent)
    base = None
    if recent:
        base = (_median([h[1] for h in recent] + [0.0] * pad), _median([h[2] for h in recent] + [0.0] * pad),
                _median([h[3] for h in recent] + [0.0] * pad))
    iat_mean = 5000.0 / packets
    row = {
        "in_packets": float(packets), "in_bytes": packets * length, "in_pkts_per_s": pps,
        "in_bytes_per_s": packets * length / 5, "out_packets": float(round(packets * out_ratio)),
        "out_bytes": round(packets * out_ratio) * 80.0, "out_in_packet_ratio": round(packets * out_ratio) / packets,
        "in_len_mean": length, "in_len_std": length * 0.1, "in_len_min": length * 0.8, "in_len_max": length * 1.2,
        "in_len_p50": length, "in_len_p95": length * 1.1,
        "in_iat_mean_ms": iat_mean if packets > 1 else math.nan, "in_iat_std_ms": iat_mean * 0.5 if packets > 1 else math.nan,
        "in_iat_min_ms": 0.0 if packets > 1 else math.nan, "in_iat_max_ms": iat_mean * 4 if packets > 1 else math.nan,
        "in_iat_cv": 0.5 if packets > 1 else math.nan,
        "in_tcp_share": tcp, "in_udp_share": 1.0 - tcp, "in_icmp_share": 0.0, "in_other_share": 0.0,
        "in_fragment_share": 0.0,
        "tcp_syn_only_ratio": (1.0 if kind == "flood-syn" else 0.02) if tcp_present else math.nan,
        "tcp_synack_reply_ratio": (0.0 if kind == "flood-syn" else 1.0) if tcp_present else math.nan,
        "tcp_rst_ratio": 0.0 if tcp_present else math.nan, "tcp_fin_ratio": 0.01 if tcp_present else math.nan,
        "tcp_psh_ratio": (0.0 if kind == "flood-syn" else 0.3) if tcp_present else math.nan,
        "tcp_ack_only_ratio": (0.0 if kind == "flood-syn" else 0.6) if tcp_present else math.nan,
        "unique_src": float(unique_src), "unique_src_prefix": float(unique_src), "src_entropy_norm": 0.0,
        "top_src_share": 1.0 / unique_src, "unique_src_ports": min(float(packets), dst_ports / 2 + 1),
        "unique_dst_ports": min(float(packets), dst_ports), "flows_active": flows_active, "flows_new": flows_new,
        "new_flows_per_s": flows_new / 5, "pkts_per_flow_mean": packets / flows_active, "pkts_per_flow_std": 0.5,
        "pkts_per_flow_max": float(packets), "bytes_per_flow_mean": packets * length / flows_active,
        "single_packet_flow_share": unanswered * 0.9, "unanswered_flow_share": unanswered,
    }
    row["in_pps_ratio_baseline"] = pps / max(base[0], 1.0) if base else math.nan
    row["new_flow_rate_ratio_baseline"] = row["new_flows_per_s"] / max(base[1], 0.2) if base else math.nan
    row["unique_src_ratio_baseline"] = unique_src / max(base[2], 1.0) if base else math.nan
    history.append((slot, pps, row["new_flows_per_s"], float(unique_src)))
    while history and history[0][0] < slot - BASELINE_WINDOWS:
        history.popleft()
    return row


def write_source(out_dir: str, seed: int, slot0: int, slots: int,
                 floods: List[Tuple[int, int, str]], bursts: int = 6) -> List[Tuple[str, int, int]]:
    """floods: (start offset, length, family) in slots. Returns (family, start_ns, end_ns) intervals."""
    rng = random.Random(seed)
    os.makedirs(out_dir)
    burst_slots = {(rng.randrange(slots), rng.choice(BENIGN_HOSTS)) for _ in range(bursts)}
    histories = {h: deque() for h in BENIGN_HOSTS + [VICTIM]}
    lines = [",".join(KEY_COLUMNS + FEATURE_NAMES)]
    for i in range(slots):
        slot = slot0 + i
        flood = next((f for f in floods if f[0] <= i < f[0] + f[1]), None)
        for host in sorted(BENIGN_HOSTS + [VICTIM]):
            if host == VICTIM:
                kind = f"flood-{flood[2]}" if flood else "normal"
            else:
                kind = "burst" if (i, host) in burst_slots else "normal"
            feats = _row(slot, host, kind, rng, histories[host])
            start = slot * WINDOW_NS
            keys = [SCHEMA_VERSION, start,
                    datetime.fromtimestamp(start // 10**9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), host]
            lines.append(",".join(str(k) for k in keys) + "," + ",".join(format_value(feats[n]) for n in FEATURE_NAMES))
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "windows.csv"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    fake = hashlib.sha256(f"SYNTHETIC-{seed}-{slot0}".encode()).hexdigest()
    with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8") as stream:
        json.dump({"schema_version": SCHEMA_VERSION, "schema_fingerprint": schema_fingerprint(),
                   "inputs": [{"path": f"SYNTHETIC-FIXTURE-{seed}", "bytes": 0, "sha256": fake}],
                   "windows_written": len(lines) - 1, "flows_written": None,
                   "counts": {"synthetic_fixture": 1}}, stream, indent=2, sort_keys=True)
    return [(fam.upper(), (slot0 + s) * WINDOW_NS, (slot0 + s + n) * WINDOW_NS) for s, n, fam in floods]


def _iso(ns: int) -> str:
    return datetime.fromtimestamp(ns // 10**9, timezone.utc).isoformat()


def build_fixture(root: str, verified: bool = True, warmup: int = 180, scale: int = 1) -> Dict[str, str]:
    """Three synthetic sources (train/validation/test), rules, plan. Returns paths."""
    specs = {
        "train": (11, SLOT0, 720 * scale, [(60, 48, "udp"), (180, 48, "syn"), (300, 48, "udp"),
                                            (420, 48, "syn"), (560, 48, "udp")]),
        "validation": (22, SLOT0 + 10_000, 480, [(80, 40, "udp"), (300, 40, "syn")]),
        "test": (33, SLOT0 + 20_000, 480, [(90, 40, "syn"), (320, 40, "udp")]),
    }
    intervals, sources = [], []
    for split, (seed, slot0, slots, floods) in specs.items():
        d = os.path.join(root, f"synthetic-{split}")
        for fam, start, end in write_source(d, seed, slot0, slots, floods):
            intervals.append({"id": f"{split}-{fam.lower()}-{start}", "family": fam,
                              "start": _iso(start), "end": _iso(end), "victims": [VICTIM]})
        sources.append({"id": f"synthetic-{split}", "dir": d, "split": split})
    rules = os.path.join(root, "rules.json")
    with open(rules, "w", encoding="utf-8") as stream:
        json.dump({"label_rules_version": "synthetic-fixture-v1", "dataset": "SYNTHETIC-FIXTURE",
                   "provenance": {"source": "tests/synthetic_windows.py (generated, not real traffic)",
                                  "verified": verified, "verified_by": "unit-test fixture",
                                  "verified_on": "2026-10-18"},
                   "guard_seconds": 5, "intervals": intervals}, stream, indent=2)
    plan = os.path.join(root, "plan.json")
    with open(plan, "w", encoding="utf-8") as stream:
        json.dump({"plan_version": "synthetic", "purge_seconds": 180, "warmup_seconds": warmup,
                   "sources": sources}, stream, indent=2)
    return {"rules": rules, "plan": plan, "victim": VICTIM}
