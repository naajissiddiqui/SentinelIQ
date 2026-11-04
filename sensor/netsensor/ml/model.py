"""
Inference: score one 5-second destination window at a time.

    from netsensor.ml.model import DosDetector, PpsHeuristic, AlertTracker
    det = DosDetector.load("bundle_dir")          # trained XGBoost bundle
    det = PpsHeuristic(threshold_pps=5000)         # or the transparent heuristic
    result = det.score_window(row)                 # row: dict with the 47 features
    tracker = AlertTracker(det.persistence)
    alert = tracker.update(row["dst_ip"], row["window_start_ns"], result["over_threshold"])

Both detectors return the same structure, carry their status (TRAINED,
SYNTHETIC_TEST_ONLY or HEURISTIC) and never read labels. Inputs are validated
by features.py: schema version, all 47 features present, no unknown fields,
no infinity, NaN only where the schema documents it.
"""

import hashlib
import json
import os
from collections import defaultdict, deque
from typing import Dict, List, Mapping, Optional, Sequence

import numpy as np

from ..schema import FEATURE_NAMES, SCHEMA_VERSION, WINDOW_NS, schema_fingerprint
from . import BUNDLE_FORMAT, STATUS_HEURISTIC, STATUS_SYNTHETIC, STATUS_TRAINED
from .features import FeatureError, Preprocessor, vector_from_mapping, vector_from_sequence

PPS_INDEX = FEATURE_NAMES.index("in_pkts_per_s")


class BundleError(ValueError):
    """The model bundle is incomplete, altered, or built for another schema."""


def _sha256(path: str) -> str:
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


class DosDetector:
    def __init__(self, bundle: Dict[str, object], booster, preprocessor: Preprocessor):
        self.bundle = bundle
        self.booster = booster
        self.preprocessor = preprocessor
        self.threshold = float(bundle["threshold"])
        self.persistence = dict(bundle["persistence"])
        self.model_version = bundle["model_version"]
        self.status = bundle["status"]
        self.rule_id = bundle.get("rule_id", "DOS-XGB")
        self._iterations = (0, int(bundle["best_iteration"]) + 1)

    @classmethod
    def load(cls, bundle_dir: str) -> "DosDetector":
        import xgboost as xgb

        path = os.path.join(bundle_dir, "bundle.json")
        if not os.path.exists(path):
            raise BundleError(f"{path} is missing")
        with open(path, encoding="utf-8") as stream:
            bundle = json.load(stream)
        if bundle.get("bundle_format") != BUNDLE_FORMAT:
            raise BundleError(f"bundle_format {bundle.get('bundle_format')!r}, expected {BUNDLE_FORMAT}")
        if bundle.get("schema_version") != SCHEMA_VERSION or bundle.get("schema_fingerprint") != schema_fingerprint():
            raise BundleError("bundle was trained for a different feature schema")
        if bundle.get("feature_names") != FEATURE_NAMES:
            raise BundleError("bundle feature order differs from the schema")
        if bundle.get("status") not in (STATUS_TRAINED, STATUS_SYNTHETIC):
            raise BundleError(f"unexpected bundle status {bundle.get('status')!r}")
        for name, digest in bundle["files"].items():
            if _sha256(os.path.join(bundle_dir, name)) != digest:
                raise BundleError(f"{name} does not match the bundle's SHA-256")
        booster = xgb.Booster()
        booster.load_model(os.path.join(bundle_dir, "model.json"))
        with open(os.path.join(bundle_dir, "preprocessing.json"), encoding="utf-8") as stream:
            pre = Preprocessor.from_dict(json.load(stream))
        return cls(bundle, booster, pre)

    def _score(self, vec: np.ndarray) -> Dict[str, object]:
        import xgboost as xgb

        dm = xgb.DMatrix(self.preprocessor.transform(vec[None, :]), missing=np.nan, feature_names=FEATURE_NAMES)
        score = float(self.booster.predict(dm, iteration_range=self._iterations)[0])
        contribs = self.booster.predict(dm, pred_contribs=True, iteration_range=self._iterations)[0][:-1]
        top = np.argsort(-np.abs(contribs))[:5]
        return {
            "score": score,
            "threshold": self.threshold,
            "over_threshold": score >= self.threshold,
            "detector": "xgboost",
            "rule_id": self.rule_id,
            "status": self.status,
            "model_version": self.model_version,
            "schema_version": SCHEMA_VERSION,
            "volume_reference_pps": self.bundle.get("pps_baseline_threshold"),
            "top_features": [{"feature": FEATURE_NAMES[i], "value": _json_num(vec[i]),
                              "contribution": round(float(contribs[i]), 6)} for i in top],
            "out_of_training_range": self.preprocessor.out_of_range(vec),
        }

    def score_window(self, row: Mapping[str, object]) -> Dict[str, object]:
        return self._score(vector_from_mapping(row))

    def score_vector(self, values: Sequence[float], names: Sequence[str]) -> Dict[str, object]:
        return self._score(vector_from_sequence(values, names))


class PpsHeuristic:
    """
    Transparent demonstration detector: alert when inbound packets per second
    reach a configured threshold for k of the last n windows.

    NOT a trained model. The default threshold is a stated policy choice, not
    a value tuned on labelled data, and no performance is claimed for it.
    """

    def __init__(self, threshold_pps: float = 5000.0, k: int = 3, n: int = 3):
        if threshold_pps <= 0 or not 1 <= k <= n:
            raise ValueError("need threshold_pps > 0 and 1 <= k <= n")
        self.threshold = float(threshold_pps)
        self.persistence = {"k": k, "n": n}
        self.model_version = f"pps-heuristic-v1-{threshold_pps:g}pps-{k}of{n}"
        self.status = STATUS_HEURISTIC
        self.rule_id = "DOS-PPS-HEURISTIC"

    def _score(self, vec: np.ndarray) -> Dict[str, object]:
        pps = float(vec[PPS_INDEX])
        return {
            "score": pps,
            "threshold": self.threshold,
            "over_threshold": pps >= self.threshold,
            "detector": "pps-heuristic",
            "rule_id": self.rule_id,
            "status": self.status,
            "model_version": self.model_version,
            "schema_version": SCHEMA_VERSION,
            "volume_reference_pps": self.threshold,
            "top_features": [{"feature": "in_pkts_per_s", "value": pps, "contribution": None}],
            "out_of_training_range": [],
        }

    def score_window(self, row: Mapping[str, object]) -> Dict[str, object]:
        return self._score(vector_from_mapping(row))

    def score_vector(self, values: Sequence[float], names: Sequence[str]) -> Dict[str, object]:
        return self._score(vector_from_sequence(values, names))


class AlertTracker:
    """
    k-of-n persistence per destination over consecutive 5-second slots (gaps count as quiet).

    `update()` returns whether the alert condition holds for this window.
    `observe()` also says whether an alert EPISODE starts here ("raised": the
    condition was false for this destination and is now true) and how many of
    the last n windows were over threshold. Raise one detection per episode,
    not one per window: an 8-minute flood is one alert, not ~96.
    """

    def __init__(self, persistence: Mapping[str, int]):
        self.k, self.n = int(persistence["k"]), int(persistence["n"])
        self._recent: Dict[str, deque] = defaultdict(deque)
        self._last_slot: Dict[str, int] = {}
        self._active: Dict[str, bool] = {}

    def observe(self, dst_ip: str, window_start_ns: int, over_threshold: bool) -> Dict[str, object]:
        slot = int(window_start_ns) // WINDOW_NS
        recent = self._recent[dst_ip]
        last = self._last_slot.get(dst_ip)
        if last is not None:
            if slot <= last:
                raise ValueError(f"windows for {dst_ip} must arrive in increasing time order")
            for _ in range(min(slot - last - 1, self.n)):
                recent.append(False)
        recent.append(bool(over_threshold))
        while len(recent) > self.n:
            recent.popleft()
        self._last_slot[dst_ip] = slot
        hits = sum(recent)
        active = hits >= self.k
        was_active = self._active.get(dst_ip, False)
        self._active[dst_ip] = active
        return {"active": active, "raised": active and not was_active, "cleared": was_active and not active,
                "hits": hits, "n": self.n}

    def update(self, dst_ip: str, window_start_ns: int, over_threshold: bool) -> bool:
        return bool(self.observe(dst_ip, window_start_ns, over_threshold)["active"])


def _json_num(value: float) -> Optional[float]:
    return None if np.isnan(value) else float(value)
