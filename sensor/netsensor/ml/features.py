"""
Feature validation and the fitted preprocessing shared by training and inference.

Model inputs are exactly schema.FEATURE_NAMES, in that order. Nothing else:
no key columns, addresses, ports, timestamps, paths or labels.

NaN policy (see netsensor/dataset.py for what each NaN means):
  - NULLABLE_FEATURES may be NaN: TCP flag ratios (no inbound TCP), inter-
    arrival statistics (a single packet), baseline ratios (no history). They
    are passed to XGBoost as missing values; the tree learns a default
    direction from the TRAINING split only.
  - Any other feature being NaN means a damaged or foreign row: rejected.
  - Infinity is always rejected.

The preprocessor's fitted state (per-feature range, median and NaN rate) is
computed from the training split only. Trees need no scaling; the state is
used to flag out-of-range inputs at inference time, as evidence for analysts.
"""

import math
from typing import Dict, List, Mapping, Sequence

import numpy as np

from ..schema import FEATURE_NAMES, KEY_COLUMNS, SCHEMA_VERSION, schema_fingerprint

NULLABLE_FEATURES = frozenset(
    [n for n in FEATURE_NAMES if n.startswith("tcp_")]
    + ["in_iat_mean_ms", "in_iat_std_ms", "in_iat_min_ms", "in_iat_max_ms", "in_iat_cv"]
    + ["in_pps_ratio_baseline", "new_flow_rate_ratio_baseline", "unique_src_ratio_baseline"]
)
_NULLABLE_MASK = np.array([n in NULLABLE_FEATURES for n in FEATURE_NAMES])


class FeatureError(ValueError):
    """A row that must not be scored: wrong schema, order, missing, NaN or infinite values."""


def vector_from_mapping(row: Mapping[str, object]) -> np.ndarray:
    """One window as a float vector in schema order. Key columns may be present; nothing else extra."""
    version = row.get("schema_version")
    if version is not None and version != SCHEMA_VERSION:
        raise FeatureError(f"schema_version {version!r}, expected {SCHEMA_VERSION}")
    missing = [n for n in FEATURE_NAMES if n not in row]
    if missing:
        raise FeatureError(f"missing features: {missing}")
    unknown = [k for k in row if k not in FEATURE_NAMES and k not in KEY_COLUMNS]
    if unknown:
        raise FeatureError(f"unexpected fields: {unknown}")
    try:
        values = np.array([float(row[n]) for n in FEATURE_NAMES], dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise FeatureError(f"non-numeric feature value: {error}") from None
    check_matrix(values[None, :])
    return values


def vector_from_sequence(values: Sequence[float], names: Sequence[str]) -> np.ndarray:
    if list(names) != FEATURE_NAMES:
        if sorted(names) == sorted(FEATURE_NAMES):
            raise FeatureError("features are in the wrong order")
        raise FeatureError("feature names do not match the dos-window-v1 schema")
    if len(values) != len(FEATURE_NAMES):
        raise FeatureError("wrong number of feature values")
    vec = np.asarray(values, dtype=np.float64)
    check_matrix(vec[None, :])
    return vec


def check_matrix(x: np.ndarray, where: str = "") -> None:
    if x.ndim != 2 or x.shape[1] != len(FEATURE_NAMES):
        raise FeatureError(f"{where}expected shape (n, {len(FEATURE_NAMES)}), got {x.shape}")
    if np.isinf(x).any():
        rows, cols = np.where(np.isinf(x))
        raise FeatureError(f"{where}infinite value in {FEATURE_NAMES[cols[0]]} (row {rows[0]})")
    bad = np.isnan(x) & ~_NULLABLE_MASK
    if bad.any():
        rows, cols = np.where(bad)
        raise FeatureError(f"{where}NaN in non-nullable feature {FEATURE_NAMES[cols[0]]} (row {rows[0]})")


class Preprocessor:
    """Validation plus training-split statistics. Transform is identity (NaN kept as missing)."""

    def __init__(self, stats: Dict[str, Dict[str, float]] = None):
        self.stats = stats or {}

    def fit(self, x_train: np.ndarray) -> "Preprocessor":
        check_matrix(x_train, "training data: ")
        self.stats = {}
        for i, name in enumerate(FEATURE_NAMES):
            col = x_train[:, i]
            finite = col[~np.isnan(col)]
            self.stats[name] = {
                "nan_rate": float(np.isnan(col).mean()),
                "min": float(finite.min()) if finite.size else math.nan,
                "max": float(finite.max()) if finite.size else math.nan,
                "median": float(np.median(finite)) if finite.size else math.nan,
            }
        return self

    def transform(self, x: np.ndarray) -> np.ndarray:
        check_matrix(x)
        return x.astype(np.float32)

    def out_of_range(self, vec: np.ndarray) -> List[str]:
        """Features outside the range seen in training (evidence, not a refusal)."""
        out = []
        for name, value in zip(FEATURE_NAMES, vec):
            s = self.stats.get(name)
            if s is None or math.isnan(value) or math.isnan(s["min"]):
                continue
            if value < s["min"] or value > s["max"]:
                out.append(name)
        return out

    def to_dict(self) -> Dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, "schema_fingerprint": schema_fingerprint(),
                "feature_names": FEATURE_NAMES, "nullable_features": sorted(NULLABLE_FEATURES),
                "fitted_on": "train split only", "stats": self.stats}

    @classmethod
    def from_dict(cls, doc: Dict[str, object]) -> "Preprocessor":
        if doc.get("schema_fingerprint") != schema_fingerprint() or doc.get("feature_names") != FEATURE_NAMES:
            raise FeatureError("preprocessor was fitted for a different feature schema")
        return cls(doc["stats"])
