"""
Evaluation report for a scored split, shared by the trained model and the
packets-per-second baseline so both are measured the same way.

Rules this report enforces:
  - Thresholds come from the VALIDATION split and are applied unchanged to
    test. Training-split numbers are labelled as fit quality, not performance.
  - Recall at a false-positive-rate target is reported only when the split
    has enough benign windows for that target to mean something (at least
    MIN_EXPECTED_FP false positives allowed by the budget); otherwise the
    entry says "not measurable" and why.
  - Proportions carry 95% Wilson intervals.
  - False alerts per benign hour count persistent (k-of-n) alerts raised on
    benign windows, per destination-hour of benign windows (each window is
    5 s of one destination's traffic).
  - Detection delay uses persistent alerts and episodes of consecutive
    attack windows (evaluate.attack_episodes).
"""

import math
from collections import Counter
from typing import Dict, List, Optional, Sequence

from .. import evaluate as ev
from ..schema import WINDOW_SECONDS

MIN_EXPECTED_FP = 5


def wilson(successes: int, n: int, z: float = 1.96) -> Optional[List[float]]:
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)]


def _num(x):
    return None if x is None or (isinstance(x, float) and math.isnan(x)) else round(float(x), 6)


def score_report(
    scores: Sequence[float],
    y: Sequence[int],
    families: Sequence[str],
    dst_ip: Sequence[str],
    window_start_ns: Sequence[int],
    threshold: float,
    persistence: Dict[str, int],
    fpr_thresholds: Dict[str, float],
) -> Dict[str, object]:
    """`fpr_thresholds`: target FPR (as text) -> threshold chosen on validation."""
    scores = [float(s) for s in scores]
    labels = [bool(v) for v in y]
    pos = sum(labels)
    neg = len(labels) - pos
    out: Dict[str, object] = {"windows": len(labels), "attack": pos, "benign": neg,
                              "attack_families": dict(Counter(f for f, l in zip(families, labels) if l))}
    if pos == 0 or neg == 0:
        out["not_measurable"] = "split needs both attack and benign windows"
        return out

    out["pr_auc"] = _num(ev.average_precision(scores, labels))
    at = ev.rates_at(scores, labels, threshold)
    tp = round(at["recall"] * pos)
    fp = round(at["fpr"] * neg)
    out["at_threshold"] = {
        "threshold": _num(threshold), "recall": _num(at["recall"]), "recall_ci95": wilson(tp, pos),
        "fpr": _num(at["fpr"]), "fpr_ci95": wilson(fp, neg), "precision": _num(at["precision"]),
        "true_positives": tp, "false_positives": fp,
    }
    targets = {}
    for target_text, t in sorted(fpr_thresholds.items(), key=lambda kv: -float(kv[0])):
        target = float(target_text)
        if neg * target < MIN_EXPECTED_FP:
            targets[target_text] = {"not_measurable": f"{neg} benign windows allow {neg * target:.2f} false "
                                                      f"positives at this rate; need >= {MIN_EXPECTED_FP}"}
            continue
        r = ev.rates_at(scores, labels, t)
        targets[target_text] = {"threshold_from_validation": _num(t), "recall": _num(r["recall"]),
                                "recall_ci95": wilson(round(r["recall"] * pos), pos),
                                "achieved_fpr": _num(r["fpr"])}
    out["recall_at_fpr_targets"] = targets
    out["recall_by_family"] = ev.recall_by_family(scores, labels, list(families), threshold)

    windows = list(zip(dst_ip, (int(s) for s in window_start_ns), scores))
    alerts = ev.persistent_alerts(windows, threshold, persistence["k"], persistence["n"])
    alert_set = {(h, a) for h, starts in alerts.items() for a in starts}
    benign_alerts = sum(1 for h, s, l in zip(dst_ip, window_start_ns, labels) if not l and (h, int(s)) in alert_set)
    benign_hours = neg * WINDOW_SECONDS / 3600
    out["false_alerts_per_benign_hour"] = {
        "persistence": persistence, "benign_destination_hours": round(benign_hours, 3),
        "false_alerts": benign_alerts, "per_hour": _num(benign_alerts / benign_hours),
    }
    episodes = ev.attack_episodes(
        (h, int(s), "attack" if l else "benign") for h, s, l in zip(dst_ip, window_start_ns, labels)
    )
    delays = ev.detection_delays(episodes, alerts)
    hit = sorted(d for d in delays if d is not None)
    out["detection_delay_s"] = {
        "episodes": len(episodes), "detected": len(hit), "missed": len(delays) - len(hit),
        "median": hit[len(hit) // 2] if hit else None, "max": hit[-1] if hit else None,
        "note": "episodes are runs of consecutive attack windows in this split; delay ends at the "
                "close of the first alerting window",
    }
    return out


def to_markdown(report: Dict[str, object]) -> str:
    lines = [f"# DoS/DDoS model evaluation — {report.get('model_version', '?')}", "",
             f"Status: **{report.get('status')}**", ""]
    for note in report.get("limitations", []):
        lines.append(f"- {note}")
    lines.append("")
    for split in ("validation", "test", "train"):
        block = report.get("splits", {}).get(split)
        if not block:
            continue
        title = {"train": "train (fit quality only, NOT performance)", "validation": "validation (threshold chosen here)",
                 "test": "test (held out)"}[split]
        lines.append(f"## {title}")
        for name in ("model", "pps_baseline"):
            r = block.get(name, {})
            lines.append(f"### {name}")
            if "not_measurable" in r:
                lines.append(f"Not measurable: {r['not_measurable']}")
                continue
            at = r["at_threshold"]
            lines.append(f"- windows {r['windows']} (attack {r['attack']}, benign {r['benign']}); PR-AUC {r['pr_auc']}")
            lines.append(f"- at threshold {at['threshold']}: recall {at['recall']} {at['recall_ci95']}, "
                         f"FPR {at['fpr']} {at['fpr_ci95']}, precision {at['precision']}")
            for target, t in r["recall_at_fpr_targets"].items():
                lines.append(f"- FPR target {target}: " + (t["not_measurable"] if "not_measurable" in t else
                             f"recall {t['recall']} {t['recall_ci95']} (achieved FPR {t['achieved_fpr']})"))
            fa = r["false_alerts_per_benign_hour"]
            lines.append(f"- false alerts per benign destination-hour: {fa['per_hour']} ({fa['false_alerts']} over "
                         f"{fa['benign_destination_hours']} h, {fa['persistence']['k']}-of-{fa['persistence']['n']})")
            d = r["detection_delay_s"]
            lines.append(f"- detection delay: median {d['median']} s, max {d['max']} s; "
                         f"{d['detected']}/{d['episodes']} episodes detected")
            lines.append(f"- recall by family: {r['recall_by_family']}")
        lines.append("")
    return "\n".join(lines) + "\n"
