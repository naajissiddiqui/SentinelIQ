"""
Train the DoS/DDoS window classifier (XGBoost) and its packets-per-second baseline.

    python -m netsensor train --dataset DATASET_DIR [--config CONFIG.json] --out-dir BUNDLE_DIR

Refuses to train (exit code 3, `training_refused.json` written) when:
  - the dataset is not usable_for_training (its label rules are unverified);
  - its warm-up exclusion is shorter than the flow idle timeout;
  - any data-sufficiency gate fails (attack/benign windows per split, attack
    episodes, families). The gates are in the config and recorded with the
    model; lowering them is a deliberate, visible decision.

Fit and selection discipline:
  - The preprocessor and the model see the TRAIN split only.
  - Early stopping and the alert threshold use VALIDATION only.
  - TEST is scored once, after everything is fixed, and reported separately.
  - The pps baseline gets its threshold the same way, at the same FPR target.

The bundle (never overwritten) holds model.json (XGBoost native format),
preprocessing.json, bundle.json (schema, threshold, persistence, config,
dataset and label provenance, library versions, file hashes) and the
evaluation report (report.json, report.md).
"""

import hashlib
import json
import os
import platform
from typing import Dict, List, Optional

import numpy as np

from .. import evaluate as ev
from ..flows import IDLE_TIMEOUT_NS
from ..schema import FEATURE_NAMES, SCHEMA_VERSION, schema_fingerprint
from . import BUNDLE_FORMAT, STATUS_SYNTHETIC, STATUS_TRAINED
from .data import Dataset, load_dataset
from .features import Preprocessor
from .report import score_report, to_markdown

PPS_INDEX = FEATURE_NAMES.index(ev.PPS_FEATURE)

DEFAULT_CONFIG: Dict[str, object] = {
    "config_version": "dos-xgb-v1",
    "seed": 20261018,
    "target_fpr": 0.001,
    "report_fpr_targets": [0.01, 0.001, 0.0001],
    "persistence": {"k": 2, "n": 3},
    "min_warmup_seconds": IDLE_TIMEOUT_NS // 1_000_000_000,
    "gates": {
        "min_attack_windows": {"train": 200, "validation": 50, "test": 50},
        "min_benign_windows": {"train": 1000, "validation": 500, "test": 500},
        "min_attack_episodes": {"train": 3, "validation": 1, "test": 1},
        "min_train_attack_families": 2,
    },
    "xgboost": {
        "n_estimators": 400, "max_depth": 4, "learning_rate": 0.1, "min_child_weight": 1.0,
        "subsample": 1.0, "colsample_bytree": 1.0, "reg_lambda": 1.0, "tree_method": "hist",
        "n_jobs": 2, "early_stopping_rounds": 30,
    },
    # Candidate overrides of "xgboost", chosen by VALIDATION average precision
    # (ties: fewer trees). An empty grid trains the "xgboost" settings as given.
    "tuning_grid": {"max_depth": [3, 4, 6], "learning_rate": [0.05, 0.1], "min_child_weight": [1.0, 5.0]},
}


class TrainingRefused(RuntimeError):
    def __init__(self, reasons: List[str], summary: Dict[str, object]):
        super().__init__("; ".join(reasons))
        self.reasons, self.summary = reasons, summary


def merged_config(user: Optional[Dict[str, object]]) -> Dict[str, object]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    for key, value in (user or {}).items():
        if key == "tuning_grid":
            cfg[key] = value  # replaced, never merged: {} turns tuning off
        elif isinstance(value, dict) and isinstance(cfg.get(key), dict):
            for k2, v2 in value.items():
                if isinstance(v2, dict) and isinstance(cfg[key].get(k2), dict):
                    cfg[key][k2].update(v2)
                else:
                    cfg[key][k2] = v2
        else:
            cfg[key] = value
    return cfg


def _episodes(split) -> int:
    rows = ((h, int(s), "attack" if y else "benign") for h, s, y in zip(split.dst_ip, split.window_start_ns, split.y))
    return len(ev.attack_episodes(rows))


def data_summary(ds: Dataset) -> Dict[str, object]:
    out = {}
    for name, s in ds.splits.items():
        fam = {}
        for f, y in zip(s.family, s.y):
            if y:
                fam[f] = fam.get(f, 0) + 1
        out[name] = {"attack": int(s.y.sum()), "benign": int(len(s) - s.y.sum()), "attack_episodes": _episodes(s),
                     "attack_families": fam, "sources": sorted(set(s.source_id))}
    return out


def check_gates(ds: Dataset, cfg: Dict[str, object]) -> List[str]:
    reasons = []
    if not ds.trusted:
        reasons.append("dataset is not usable_for_training (label rules unverified or absent)")
    warmup = ds.manifest.get("plan", {}).get("warmup_seconds", 0)
    if warmup < cfg["min_warmup_seconds"]:
        reasons.append(f"dataset warmup_seconds {warmup} < {cfg['min_warmup_seconds']} (cold-start rows would be used)")
    summary = data_summary(ds)
    g = cfg["gates"]
    for split in ("train", "validation", "test"):
        s = summary[split]
        if s["attack"] < g["min_attack_windows"][split]:
            reasons.append(f"{split}: {s['attack']} attack windows < {g['min_attack_windows'][split]}")
        if s["benign"] < g["min_benign_windows"][split]:
            reasons.append(f"{split}: {s['benign']} benign windows < {g['min_benign_windows'][split]}")
        if s["attack_episodes"] < g["min_attack_episodes"][split]:
            reasons.append(f"{split}: {s['attack_episodes']} attack episodes < {g['min_attack_episodes'][split]}")
    if len(summary["train"]["attack_families"]) < g["min_train_attack_families"]:
        reasons.append(f"train: {len(summary['train']['attack_families'])} attack families "
                       f"< {g['min_train_attack_families']}")
    return reasons


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fpr_thresholds(scores: np.ndarray, y: np.ndarray, targets: List[float]) -> Dict[str, float]:
    return {repr(t): ev.threshold_for_fpr(scores.tolist(), [bool(v) for v in y], t) for t in targets}


def train(dataset_dir: str, out_dir: str, user_config: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    import sklearn
    import xgboost as xgb

    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise FileExistsError(f"refusing to overwrite {out_dir}")
    cfg = merged_config(user_config)
    cfg_text = json.dumps(cfg, sort_keys=True)
    ds = load_dataset(dataset_dir)
    reasons = check_gates(ds, cfg)
    summary = {"dataset": ds.path, "manifest_sha256": ds.manifest_sha256, "usable_for_training": ds.trusted,
               "splits": data_summary(ds), "dropped_rows": ds.dropped, "gates": cfg["gates"],
               "min_warmup_seconds": cfg["min_warmup_seconds"]}
    if reasons:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "training_refused.json"), "w", encoding="utf-8", newline="\n") as stream:
            json.dump({"refused": True, "reasons": reasons, **summary}, stream, indent=2, sort_keys=True)
            stream.write("\n")
        raise TrainingRefused(reasons, summary)

    tr, va, te = ds.splits["train"], ds.splits["validation"], ds.splits["test"]
    pre = Preprocessor().fit(tr.x)
    x_tr, x_va, x_te = pre.transform(tr.x), pre.transform(va.x), pre.transform(te.x)
    pos, neg = int(tr.y.sum()), int(len(tr) - tr.y.sum())
    def fit(params):
        m = xgb.XGBClassifier(objective="binary:logistic", eval_metric="aucpr", random_state=cfg["seed"],
                              scale_pos_weight=neg / pos, missing=np.nan, **params)
        m.fit(x_tr, tr.y, eval_set=[(x_va, va.y)], verbose=False)
        return m

    tuning = []
    grid = cfg.get("tuning_grid") or {}
    candidates = [dict(cfg["xgboost"])]
    if grid:
        import itertools
        names = sorted(grid)
        candidates = [dict(cfg["xgboost"], **dict(zip(names, combo)))
                      for combo in itertools.product(*(grid[n] for n in names))]
    model, best_key = None, None
    for params in candidates:
        m = fit(params)
        ap = ev.average_precision(m.predict_proba(x_va)[:, 1].tolist(), [bool(v) for v in va.y])
        trees = int(getattr(m, "best_iteration", params["n_estimators"] - 1)) + 1
        tuning.append({"params": {k: params[k] for k in sorted(grid)} if grid else {}, "validation_pr_auc": ap,
                       "trees": trees})
        key = (ap, -trees)
        if best_key is None or key > best_key:
            model, best_key, params_used = m, key, params
    params = params_used

    s_tr, s_va, s_te = (model.predict_proba(x)[:, 1] for x in (x_tr, x_va, x_te))
    p_tr, p_va, p_te = tr.x[:, PPS_INDEX], va.x[:, PPS_INDEX], te.x[:, PPS_INDEX]
    targets = list(cfg["report_fpr_targets"])
    model_thr = ev.threshold_for_fpr(s_va.tolist(), [bool(v) for v in va.y], cfg["target_fpr"])
    pps_thr = ev.threshold_for_fpr(p_va.tolist(), [bool(v) for v in va.y], cfg["target_fpr"])
    model_targets = _fpr_thresholds(s_va, va.y, targets)
    pps_targets = _fpr_thresholds(p_va, va.y, targets)

    def block(split, scores, pps):
        common = (split.y, split.family, split.dst_ip, split.window_start_ns)
        return {"model": score_report(scores, *common, model_thr, cfg["persistence"], model_targets),
                "pps_baseline": score_report(pps, *common, pps_thr, cfg["persistence"], pps_targets)}

    labels_info = ds.manifest.get("labels", {})
    synthetic = str(labels_info.get("dataset", "")).upper().startswith("SYNTHETIC")
    status = STATUS_SYNTHETIC if synthetic else STATUS_TRAINED
    os.makedirs(out_dir, exist_ok=True)
    model_path = os.path.join(out_dir, "model.json")
    model.get_booster().save_model(model_path)
    pre_doc = pre.to_dict()
    pre_text = json.dumps(pre_doc, indent=2, sort_keys=True) + "\n"
    with open(os.path.join(out_dir, "preprocessing.json"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(pre_text)
    with open(model_path, "rb") as stream:
        model_sha = _sha256_bytes(stream.read())
    version = f"dos-xgb-{ds.manifest_sha256[:8]}-{_sha256_bytes(cfg_text.encode())[:8]}"
    bundle = {
        "bundle_format": BUNDLE_FORMAT,
        "model_version": version,
        "status": status,
        "detector": "xgboost",
        "rule_id": "DOS-XGB",
        "schema_version": SCHEMA_VERSION,
        "schema_fingerprint": schema_fingerprint(),
        "feature_names": FEATURE_NAMES,
        "threshold": model_thr,
        "target_fpr": cfg["target_fpr"],
        "persistence": cfg["persistence"],
        "pps_baseline_threshold": pps_thr,
        "best_iteration": int(getattr(model, "best_iteration", params["n_estimators"] - 1)),
        "xgboost_params_used": params,
        "tuning": {"selected_by": "validation average precision (ties: fewer trees)", "candidates": tuning},
        "config": cfg,
        "config_sha256": _sha256_bytes(cfg_text.encode()),
        "training_data": summary,
        "labels": labels_info,
        "sources": [{"id": s["id"], "captures": s["captures"]} for s in ds.manifest.get("sources", [])],
        "libraries": {"python": platform.python_version(), "xgboost": xgb.__version__,
                      "scikit_learn": sklearn.__version__, "numpy": np.__version__},
        "files": {"model.json": model_sha, "preprocessing.json": _sha256_bytes(pre_text.encode())},
    }
    report = {
        "model_version": version, "status": status,
        "splits": {"validation": block(va, s_va, p_va), "test": block(te, s_te, p_te),
                   "train": block(tr, s_tr, p_tr)},
        "limitations": _limitations(ds, status) + ([
            "Hyperparameters, early stopping and the threshold were all selected on the validation split, so "
            "validation metrics are optimistic; only test metrics are unbiased."] if grid else []),
    }
    for name, doc in (("bundle.json", bundle), ("report.json", report)):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as stream:
            json.dump(doc, stream, indent=2, sort_keys=True)
            stream.write("\n")
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(to_markdown(report))
    return bundle


def _limitations(ds: Dataset, status: str) -> List[str]:
    notes = []
    if status == STATUS_SYNTHETIC:
        notes.append("SYNTHETIC test fixture data: these numbers test the software, not detection performance.")
    sources = {s for split in ds.splits.values() for s in split.source_id}
    notes.append(f"{len(sources)} capture source(s); results do not generalise beyond the traffic they contain.")
    victims = {h for split in ds.splits.values() for h, y in zip(split.dst_ip, split.y) if y}
    if len(victims) <= 1:
        notes.append("All attack windows target a single destination host.")
    notes.append("Ambiguous, warm-up, purged and unassigned windows are excluded, so low-rate attack traffic "
                 "the labels could not place is not evaluated.")
    return notes
