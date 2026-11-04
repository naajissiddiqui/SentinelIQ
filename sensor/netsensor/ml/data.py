"""
Load a built window dataset (netsensor/dataset.py) for training and evaluation.

Checks, in order, before any row is used:
  - dataset format, schema version and fingerprint, feature names and order;
  - SHA-256 of features/labels/splits against the manifest;
  - features.csv, labels.csv and splits.csv carry the same key on every line;
  - no window key appears twice.

Only rows labelled "attack" or "benign" in train/validation/test are
returned. "ambiguous", "unlabelled", "purged", "unassigned" and "warmup" rows
are counted and dropped, never relabelled.
"""

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

import numpy as np

from ..dataset import DATASET_FORMAT, SPLITS, sha256_file
from ..schema import FEATURE_NAMES, KEY_COLUMNS, SCHEMA_VERSION, schema_fingerprint
from .features import check_matrix

USABLE_LABELS = ("attack", "benign")


class DataError(ValueError):
    """The dataset cannot be used: wrong schema, changed files, misaligned or duplicated rows."""


@dataclass
class Split:
    x: np.ndarray
    y: np.ndarray                 # 1 = attack, 0 = benign
    source_id: List[str]
    window_start_ns: np.ndarray
    dst_ip: List[str]
    family: List[str]

    def __len__(self) -> int:
        return len(self.y)


@dataclass
class Dataset:
    path: str
    manifest: Dict[str, object]
    manifest_sha256: str
    splits: Dict[str, Split]
    dropped: Dict[str, int] = field(default_factory=dict)

    @property
    def trusted(self) -> bool:
        return bool(self.manifest.get("usable_for_training"))


def load_dataset(path: str) -> Dataset:
    manifest_path = os.path.join(path, "manifest.json")
    with open(manifest_path, encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("dataset_format") != DATASET_FORMAT:
        raise DataError(f"dataset_format {manifest.get('dataset_format')!r}, expected {DATASET_FORMAT}")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("schema_fingerprint") != schema_fingerprint():
        raise DataError("dataset was built for a different feature schema")
    if manifest.get("feature_names") != FEATURE_NAMES:
        raise DataError("dataset feature names or order differ from the schema")
    for name, digest in manifest.get("files", {}).items():
        if sha256_file(os.path.join(path, name)) != digest:
            raise DataError(f"{name} changed since the dataset was built")

    header = ["source_id"] + KEY_COLUMNS + FEATURE_NAMES
    n_keys = 1 + len(KEY_COLUMNS)
    rows: Dict[str, Dict[str, list]] = {s: {"x": [], "y": [], "src": [], "start": [], "dst": [], "fam": []} for s in SPLITS}
    dropped: Dict[str, int] = {}
    seen = set()
    with open(os.path.join(path, "features.csv"), newline="", encoding="utf-8") as f_feat, \
         open(os.path.join(path, "labels.csv"), newline="", encoding="utf-8") as f_lab, \
         open(os.path.join(path, "splits.csv"), newline="", encoding="utf-8") as f_split:
        feats, labs, splits = csv.reader(f_feat), csv.reader(f_lab), csv.reader(f_split)
        if next(feats) != header:
            raise DataError("features.csv header does not match the schema")
        next(labs)
        next(splits)
        for line_no, (fr, lr, sr) in enumerate(zip(feats, labs, splits), start=2):
            key = (fr[0], fr[2], fr[4])  # source_id, window_start_ns, dst_ip
            if (lr[0], lr[1], lr[2]) != key or (sr[0], sr[1], sr[2]) != key:
                raise DataError(f"line {line_no}: features, labels and splits are not aligned")
            if key in seen:
                raise DataError(f"line {line_no}: duplicate window {key}")
            seen.add(key)
            label, split = lr[3], sr[3]
            if label not in USABLE_LABELS or split not in SPLITS:
                reason = f"{split}/{label}"
                dropped[reason] = dropped.get(reason, 0) + 1
                continue
            r = rows[split]
            r["x"].append([float(v) for v in fr[n_keys:]])
            r["y"].append(1 if label == "attack" else 0)
            r["src"].append(fr[0])
            r["start"].append(int(fr[2]))
            r["dst"].append(fr[4])
            r["fam"].append(lr[4])
        for leftover in (next(feats, None), next(labs, None), next(splits, None)):
            if leftover is not None:
                raise DataError("features, labels and splits have different row counts")

    out = {}
    for s, r in rows.items():
        x = np.array(r["x"], dtype=np.float64).reshape(-1, len(FEATURE_NAMES))
        check_matrix(x, f"{s} split: ")
        out[s] = Split(x, np.array(r["y"], dtype=np.int8), r["src"], np.array(r["start"], dtype=np.int64),
                       r["dst"], r["fam"])
    return Dataset(os.path.abspath(path), manifest, sha256_file(manifest_path), out, dict(sorted(dropped.items())))
