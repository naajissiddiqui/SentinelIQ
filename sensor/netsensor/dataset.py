"""
Extraction outputs -> a labelled, split, provenance-tracked window dataset (D3).

Input is a PLAN (JSON) naming finished extraction directories and how their
rows are split, plus optional label rules (labels.py):

    {
      "plan_version": "sample-v1",
      "purge_seconds": 180,
      "sources": [
        {"id": "pre",   "dir": "C:/datasets/x/run1",  "split": "train"},
        {"id": "day",   "dir": "C:/datasets/x/day",
         "blocks": [{"from": "2018-11-03T12:00:00+00:00", "to": "2018-11-03T13:20:00+00:00", "split": "train"},
                    {"from": "2018-11-03T13:20:00+00:00", "to": "2018-11-03T15:00:00+00:00", "split": "test"}]}
      ]
    }

Outputs (the builder never overwrites; every row of every source appears in
all three CSVs, in the same order, keyed by source_id + window_start_ns + dst_ip):
  - features.csv  source_id, KEY_COLUMNS, FEATURE_NAMES (values copied verbatim)
  - labels.csv    key, label, family, interval_id      (never mixed with features)
  - splits.csv    key, split
  - manifest.json schema fingerprint, source hashes and capture hashes, plan,
                  label provenance, counts, NaN report, exclusions

Leakage controls:
  - A capture file (by SHA-256 in stats.json) may appear in ONE source only,
    so no capture lands in two splits and no window is counted twice.
  - Splits are assigned explicitly by source or by time block, never by a
    random row shuffle: consecutive windows of one flood are near-duplicates.
  - Window features look back up to 120 s (flow idle timeout) and 60 s
    (baseline). Rows within purge_seconds of a boundary between DIFFERENT
    splits, on either side, are marked "purged" and must not be used.
  - Rows outside every block are "unassigned".
  - Each source is one independent extraction that starts with an empty flow
    table and no baseline history. Rows whose window starts within
    warmup_seconds (plan field, default 0; use >= 180) of the source's first
    window are marked "warmup" and must not be used.

NaN and infinity:
  - Infinity is rejected: the extractor never writes it, so one means a
    damaged file and the build fails with its location.
  - NaN is kept as "nan". Every NaN the extractor writes has a documented
    meaning (no inbound TCP, a single packet, no baseline history), so it is
    information, not damage. The NaN count per feature and split is recorded.
    Gradient-boosted trees use it natively (learned default direction, from
    the training split only); a model that cannot must impute from the
    training split only. The packets-per-second baseline uses in_pkts_per_s,
    which is never NaN; the builder checks that.

Memory: rows are streamed; only each source's set of window keys is held
(duplicate detection), about a hundred bytes per window.
"""

import csv
import hashlib
import json
import math
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .labels import UNLABELLED, LabelRules, describe
from .schema import (
    FEATURE_NAMES,
    KEY_COLUMNS,
    SCHEMA_VERSION,
    WINDOW_NS,
    schema_fingerprint,
)

DATASET_FORMAT = "dos-window-dataset-v1"
SPLITS = ("train", "validation", "test")
PURGED = "purged"
UNASSIGNED = "unassigned"
WARMUP = "warmup"
ROW_KEY = ["source_id", "window_start_ns", "dst_ip"]


class DatasetError(ValueError):
    """A source, plan or row that cannot be used. A failed build leaves no output files."""


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _time_ns(value: object, where: str) -> int:
    if not isinstance(value, str):
        raise DatasetError(f"{where}: time must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise DatasetError(f"{where}: {error}") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DatasetError(f"{where}: time {value!r} has no UTC offset")
    whole = int(parsed.replace(microsecond=0).timestamp())
    return whole * 1_000_000_000 + parsed.microsecond * 1_000


class SplitAssigner:
    """Maps a window start to its split for one source, with purge zones."""

    def __init__(self, entry: Dict[str, object], purge_ns: int, where: str):
        self.blocks: List[Tuple[int, int, str]] = []
        if "split" in entry and "blocks" in entry:
            raise DatasetError(f"{where}: give either split or blocks, not both")
        if "split" in entry:
            self._check(entry["split"], where)
            self.blocks = [(-(2**62), 2**62, entry["split"])]
        elif "blocks" in entry:
            for i, b in enumerate(entry["blocks"]):
                w = f"{where}.blocks[{i}]"
                lo, hi = _time_ns(b.get("from"), f"{w}.from"), _time_ns(b.get("to"), f"{w}.to")
                if hi <= lo:
                    raise DatasetError(f"{w}: to is not after from")
                self._check(b.get("split"), w)
                self.blocks.append((lo, hi, b["split"]))
            self.blocks.sort()
            for (_, a_hi, _), (b_lo, _, _) in zip(self.blocks, self.blocks[1:]):
                if b_lo < a_hi:
                    raise DatasetError(f"{where}: blocks overlap")
        else:
            raise DatasetError(f"{where}: needs split or blocks")
        # Boundaries where the split changes (a gap between blocks counts as one).
        self.cuts: List[int] = []
        for (_, a_hi, a_split), (b_lo, _, b_split) in zip(self.blocks, self.blocks[1:]):
            if a_split != b_split or b_lo > a_hi:
                self.cuts += [a_hi, b_lo]
        self.purge_ns = purge_ns

    @staticmethod
    def _check(split: object, where: str) -> None:
        if split not in SPLITS:
            raise DatasetError(f"{where}: split must be one of {SPLITS}, got {split!r}")

    def assign(self, window_start_ns: int) -> str:
        w_end = window_start_ns + WINDOW_NS
        for lo, hi, split in self.blocks:
            if lo <= window_start_ns and w_end <= hi:
                for cut in self.cuts:
                    if window_start_ns < cut + self.purge_ns and w_end > cut - self.purge_ns:
                        return PURGED
                return split
        return UNASSIGNED


def load_plan(path: str) -> Tuple[Dict[str, object], str]:
    with open(path, "rb") as stream:
        data = stream.read()
    try:
        plan = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DatasetError(f"plan is not valid JSON: {error}") from None
    for key in ("plan_version", "purge_seconds", "sources"):
        if key not in plan:
            raise DatasetError(f"plan is missing {key}")
    purge = plan["purge_seconds"]
    if not isinstance(purge, (int, float)) or isinstance(purge, bool) or purge < 0:
        raise DatasetError("purge_seconds must be a non-negative number")
    warmup = plan.setdefault("warmup_seconds", 0)
    if not isinstance(warmup, (int, float)) or isinstance(warmup, bool) or warmup < 0:
        raise DatasetError("warmup_seconds must be a non-negative number")
    ids = [s.get("id") for s in plan["sources"]]
    if not ids or any(not i for i in ids) or len(set(ids)) != len(ids):
        raise DatasetError("every source needs a unique, non-empty id")
    return plan, hashlib.sha256(data).hexdigest()


def _read_source_stats(src_dir: str, where: str) -> Dict[str, object]:
    path = os.path.join(src_dir, "stats.json")
    if not os.path.exists(path):
        raise DatasetError(f"{where}: {path} is missing (extraction did not finish)")
    with open(path, encoding="utf-8") as stream:
        stats = json.load(stream)
    if stats.get("schema_version") != SCHEMA_VERSION:
        raise DatasetError(f"{where}: schema {stats.get('schema_version')!r}, expected {SCHEMA_VERSION}")
    if stats.get("schema_fingerprint") != schema_fingerprint():
        raise DatasetError(f"{where}: schema fingerprint differs from this code's schema")
    for item in stats.get("inputs", []):
        if not item.get("sha256"):
            raise DatasetError(f"{where}: input {item.get('path')} has no SHA-256 (extracted with --no-hash)")
    if not stats.get("inputs"):
        raise DatasetError(f"{where}: stats.json lists no inputs")
    return stats


def build_dataset(
    plan_path: str,
    out_dir: str,
    rules: Optional[LabelRules] = None,
) -> Dict[str, object]:
    plan, plan_sha = load_plan(plan_path)
    purge_ns = int(round(plan["purge_seconds"] * 1_000_000_000))
    plan_dir = os.path.dirname(os.path.abspath(plan_path))

    # Validate every source before writing anything.
    sources = []
    capture_owner: Dict[str, str] = {}
    for entry in plan["sources"]:
        where = f"source {entry['id']!r}"
        src_dir = entry.get("dir")
        if not src_dir:
            raise DatasetError(f"{where}: dir is required")
        if not os.path.isabs(src_dir):
            src_dir = os.path.join(plan_dir, src_dir)
        stats = _read_source_stats(src_dir, where)
        for item in stats["inputs"]:
            owner = capture_owner.setdefault(item["sha256"], entry["id"])
            if owner != entry["id"]:
                raise DatasetError(
                    f"capture {item['path']} (sha256 {item['sha256'][:12]}...) is in sources "
                    f"{owner!r} and {entry['id']!r}; a capture may appear in one source only"
                )
        sources.append((entry, src_dir, stats, SplitAssigner(entry, purge_ns, where)))

    os.makedirs(out_dir, exist_ok=True)
    targets = {n: os.path.join(out_dir, n) for n in ("features.csv", "labels.csv", "splits.csv", "manifest.json")}
    existing = [p for t in targets.values() for p in (t, t + ".partial") if os.path.exists(p)]
    if existing:
        raise FileExistsError(f"refusing to overwrite {existing}")
    # Written as *.partial and renamed only when every row has passed, so a
    # failed build leaves no dataset that looks complete.
    try:
        manifest = _write(sources, plan, plan_path, plan_sha, rules, targets)
    except BaseException:
        for path in targets.values():
            if os.path.exists(path + ".partial"):
                os.remove(path + ".partial")
        raise
    for path in targets.values():
        os.replace(path + ".partial", path)
    return manifest


def _write(sources, plan, plan_path, plan_sha, rules, targets) -> Dict[str, object]:
    partial = {name: path + ".partial" for name, path in targets.items()}
    warmup_ns = int(round(plan["warmup_seconds"] * 1_000_000_000))
    counts: Counter = Counter()
    nan_counts: Dict[str, Counter] = defaultdict(Counter)
    source_records = []
    header = KEY_COLUMNS + FEATURE_NAMES
    pps_index = header.index("in_pkts_per_s")
    with open(partial["features.csv"], "w", newline="", encoding="utf-8") as f_feat, \
         open(partial["labels.csv"], "w", newline="", encoding="utf-8") as f_lab, \
         open(partial["splits.csv"], "w", newline="", encoding="utf-8") as f_split:
        w_feat = csv.writer(f_feat, lineterminator="\n")
        w_lab = csv.writer(f_lab, lineterminator="\n")
        w_split = csv.writer(f_split, lineterminator="\n")
        w_feat.writerow(["source_id"] + header)
        w_lab.writerow(ROW_KEY + ["label", "family", "interval_id"])
        w_split.writerow(ROW_KEY + ["split"])

        for entry, src_dir, stats, assigner in sources:
            sid = entry["id"]
            windows_path = os.path.join(src_dir, "windows.csv")
            rows = 0
            keys = set()
            first_slot = last_slot = None
            warm_end = None
            per_source: Counter = Counter()
            with open(windows_path, newline="", encoding="utf-8") as stream:
                reader = csv.reader(stream)
                if next(reader, None) != header:
                    raise DatasetError(f"{windows_path}: header is not KEY_COLUMNS + FEATURE_NAMES")
                for line_no, row in enumerate(reader, start=2):
                    where = f"{windows_path}:{line_no}"
                    if len(row) != len(header):
                        raise DatasetError(f"{where}: {len(row)} columns, expected {len(header)}")
                    if row[0] != SCHEMA_VERSION:
                        raise DatasetError(f"{where}: schema_version {row[0]!r}")
                    start_ns = int(row[1])
                    if start_ns % WINDOW_NS:
                        raise DatasetError(f"{where}: window start not on the {WINDOW_NS} ns grid")
                    key = (start_ns, row[3])
                    if key in keys:
                        raise DatasetError(f"{where}: duplicate window key {key}")
                    keys.add(key)
                    if warm_end is None:
                        warm_end = start_ns + warmup_ns  # rows come in window order
                    split = WARMUP if start_ns < warm_end else assigner.assign(start_ns)
                    for name, text in zip(FEATURE_NAMES, row[len(KEY_COLUMNS):]):
                        value = float(text)
                        if math.isinf(value):
                            raise DatasetError(f"{where}: {name} is infinite")
                        if math.isnan(value):
                            nan_counts[split][name] += 1
                    if math.isnan(float(row[pps_index])):
                        raise DatasetError(f"{where}: in_pkts_per_s is NaN")
                    label, family, interval_id = (
                        rules.label(start_ns, row[3]) if rules is not None else (UNLABELLED, "", "")
                    )
                    w_feat.writerow([sid] + row)
                    w_lab.writerow([sid, row[1], row[3], label, family, interval_id])
                    w_split.writerow([sid, row[1], row[3], split])
                    counts[(split, label, family)] += 1
                    per_source[(split, label)] += 1
                    rows += 1
                    slot = start_ns // WINDOW_NS
                    first_slot = slot if first_slot is None else min(first_slot, slot)
                    last_slot = slot if last_slot is None else max(last_slot, slot)
            if rows != stats.get("windows_written"):
                raise DatasetError(
                    f"{windows_path}: {rows} rows but stats.json says {stats.get('windows_written')}"
                )
            source_records.append({
                "id": sid,
                "dir": os.path.abspath(src_dir),
                "windows_sha256": sha256_file(windows_path),
                "stats_sha256": sha256_file(os.path.join(src_dir, "stats.json")),
                "captures": stats["inputs"],
                "extraction_counts": stats.get("counts", {}),
                "rows": rows,
                "first_window_start_ns": first_slot * WINDOW_NS if rows else None,
                "last_window_start_ns": last_slot * WINDOW_NS if rows else None,
                "assignment": {k: entry[k] for k in ("split", "blocks") if k in entry},
                "rows_by_split_and_label": {f"{s}/{l}": n for (s, l), n in sorted(per_source.items())},
            })

    manifest = {
        "dataset_format": DATASET_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "schema_fingerprint": schema_fingerprint(),
        "feature_names": FEATURE_NAMES,
        "plan": {"path": os.path.abspath(plan_path), "sha256": plan_sha,
                 "plan_version": plan["plan_version"], "purge_seconds": plan["purge_seconds"],
                 "warmup_seconds": plan["warmup_seconds"]},
        "labels": describe(rules),
        "sources": source_records,
        "rows_total": sum(counts.values()),
        "rows_by_split_label_family": [
            {"split": s, "label": l, "family": f, "rows": n} for (s, l, f), n in sorted(counts.items())
        ],
        "nan_by_split_and_feature": {s: dict(sorted(c.items())) for s, c in sorted(nan_counts.items())},
        "files": {
            name: sha256_file(path) for name, path in sorted(partial.items()) if name != "manifest.json"
        },
        "usable_for_training": bool(rules is not None and rules.verified),
    }
    with open(partial["manifest.json"], "w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return manifest
