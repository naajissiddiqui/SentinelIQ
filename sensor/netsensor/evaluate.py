"""
Window-level evaluation metrics and the packets-per-second baseline (D4).

Standard library only, so the same numbers come out wherever it runs. Every
function takes scores and labels the caller has already restricted to usable
rows: label "attack" (positive) or "benign" (negative) in the split being
evaluated. "ambiguous", "unlabelled", "purged" and "unassigned" rows never
reach these functions.

Decisions:
  - PR-AUC is average precision: sum over thresholds of (R_n - R_{n-1}) * P_n,
    with tied scores treated as one threshold (no interpolation).
  - A threshold for "recall at FPR <= x" is chosen on the VALIDATION split
    and then applied unchanged to the test split, where the achieved FPR is
    reported next to the recall. Choosing it on test would flatter the model.
  - Alerts use a k-of-n persistence rule per destination over consecutive
    5-second slots; a missing slot counts as "not over threshold".
  - Detection delay for an attack episode (consecutive attack windows of one
    destination) runs from the start of its first window to the END of the
    window that raised the first alert, because a window can only be scored
    once it has closed. An episode with no alert is a miss, not a delay.
"""

import math
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .schema import WINDOW_NS

PPS_FEATURE = "in_pkts_per_s"


def pps_baseline_score(row: Dict[str, float]) -> float:
    """The baseline detector: inbound packets per second, nothing else."""
    return float(row[PPS_FEATURE])


def _check(scores: Sequence[float], labels: Sequence[bool]) -> None:
    if len(scores) != len(labels):
        raise ValueError("scores and labels differ in length")
    if any(math.isnan(s) for s in scores):
        raise ValueError("NaN score")


def average_precision(scores: Sequence[float], labels: Sequence[bool]) -> float:
    _check(scores, labels)
    positives = sum(1 for y in labels if y)
    if positives == 0:
        return math.nan
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    ap = tp = fp = 0
    prev_recall = 0.0
    i = 0
    while i < len(order):
        j = i
        while j < len(order) and scores[order[j]] == scores[order[i]]:
            if labels[order[j]]:
                tp += 1
            else:
                fp += 1
            j += 1
        recall = tp / positives
        ap += (recall - prev_recall) * (tp / (tp + fp))
        prev_recall = recall
        i = j
    return ap


def threshold_for_fpr(scores: Sequence[float], labels: Sequence[bool], max_fpr: float) -> float:
    """Lowest threshold (alert when score >= t) whose FPR on these rows is <= max_fpr."""
    _check(scores, labels)
    negatives = sorted((s for s, y in zip(scores, labels) if not y), reverse=True)
    if not negatives:
        raise ValueError("no negative rows to set a false-positive rate on")
    allowed = math.floor(max_fpr * len(negatives) + 1e-12)
    # Alerting at t flags every negative with score >= t. With `allowed`
    # false positives permitted, t must sit just above negative number allowed.
    if allowed >= len(negatives):
        return -math.inf
    return math.nextafter(negatives[allowed], math.inf)


def rates_at(scores: Sequence[float], labels: Sequence[bool], threshold: float) -> Dict[str, float]:
    _check(scores, labels)
    tp = sum(1 for s, y in zip(scores, labels) if y and s >= threshold)
    fp = sum(1 for s, y in zip(scores, labels) if not y and s >= threshold)
    pos = sum(1 for y in labels if y)
    neg = len(labels) - pos
    return {
        "threshold": threshold,
        "recall": tp / pos if pos else math.nan,
        "fpr": fp / neg if neg else math.nan,
        "precision": tp / (tp + fp) if tp + fp else math.nan,
        "positives": pos,
        "negatives": neg,
    }


def recall_by_family(
    scores: Sequence[float], labels: Sequence[bool], families: Sequence[str], threshold: float
) -> Dict[str, Dict[str, float]]:
    """Recall per attack family at one threshold. Benign rows have family ''."""
    out: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    for s, y, fam in zip(scores, labels, families):
        if y:
            out[fam][1] += 1
            if s >= threshold:
                out[fam][0] += 1
    return {fam: {"recall": hit / n, "positives": n} for fam, (hit, n) in sorted(out.items())}


def persistent_alerts(
    windows: Iterable[Tuple[str, int, float]], threshold: float, k: int, n: int
) -> Dict[str, List[int]]:
    """
    windows: (dst_ip, window_start_ns, score). Returns, per destination, the
    window starts at which an alert is raised: at least k of the last n slots
    (this one included) scored >= threshold.
    """
    if not 1 <= k <= n:
        raise ValueError("need 1 <= k <= n")
    by_host: Dict[str, Dict[int, float]] = defaultdict(dict)
    for host, start, score in windows:
        by_host[host][start // WINDOW_NS] = score
    alerts: Dict[str, List[int]] = {}
    for host, slots in sorted(by_host.items()):
        raised = []
        recent: deque = deque()
        for slot in range(min(slots), max(slots) + 1):
            recent.append(slot in slots and slots[slot] >= threshold)
            if len(recent) > n:
                recent.popleft()
            if slot in slots and sum(recent) >= k:
                raised.append(slot * WINDOW_NS)
        alerts[host] = raised
    return alerts


def attack_episodes(rows: Iterable[Tuple[str, int, str]]) -> List[Tuple[str, int, int]]:
    """
    rows: (dst_ip, window_start_ns, label). An episode is a run of consecutive
    "attack" slots for one destination; an "ambiguous" slot neither breaks nor
    extends a run. Returns (dst_ip, first_start_ns, last_start_ns).
    """
    by_host: Dict[str, Dict[int, str]] = defaultdict(dict)
    for host, start, label in rows:
        by_host[host][start // WINDOW_NS] = label
    episodes = []
    for host, slots in sorted(by_host.items()):
        first = last = None
        for slot in range(min(slots), max(slots) + 2):
            label = slots.get(slot)
            if label == "attack":
                first = slot if first is None else first
                last = slot
            elif label == "ambiguous" and first is not None:
                continue
            elif first is not None:
                episodes.append((host, first * WINDOW_NS, last * WINDOW_NS))
                first = last = None
    return episodes


def detection_delays(
    episodes: Sequence[Tuple[str, int, int]], alerts: Dict[str, List[int]]
) -> List[Optional[float]]:
    """Seconds from episode start to the end of the first alerting window inside it; None = missed."""
    delays: List[Optional[float]] = []
    for host, first, last in episodes:
        hit = next((a for a in alerts.get(host, []) if first <= a <= last), None)
        delays.append(None if hit is None else (hit + WINDOW_NS - first) / 1e9)
    return delays
