# SentinelIQ network sensor (`netsensor`)

Offline DoS/DDoS feature extraction from **recorded** PCAP/pcapng files. This
package is separate from the Windows agent and its Sysmon/ransomware pipeline.
It reads files only: it never captures from or transmits on a network.
Design and phases: `IMPLEMENTATION_PLAN.md` §4 and §7 (D1–D8). Implemented:
D2 (extraction), D3 (dataset build, label rules), D4 tooling (training,
evaluation, inference). **No supervised model is trained yet**: the label rules
are unverified and the labelled data fails the training gates (see "Model status").

## Setup and tests

Extraction, dataset building and the job runner use only the Python standard
library (the sensor venv has no packages). Training, evaluation and scoring
need numpy, scikit-learn and xgboost, taken from the ml-service venv
(`netsensor/ml/`, imported lazily).

```powershell
cd sensor
& "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -t .                     # ML tests skipped
..\apps\ml-service\.venv\Scripts\python.exe -B -m unittest discover -s tests -t .    # everything
```

The tests use a few hand-built **benign** packets (`tests/pcap_builder.py`) and
**synthetic** window fixtures (`tests/synthetic_windows.py`). Both exist only to
test software behaviour. They are never training data or demonstration evidence;
a model trained on the synthetic fixture is stamped `SYNTHETIC_TEST_ONLY`, and the
backend refuses alerts from it.

## Extract

```powershell
.\.venv\Scripts\python.exe -m netsensor extract --out-dir out\day1 capture-01.pcap capture-02.pcap
```

Files are processed in the order given, as one continuous capture. The command writes:

- `windows.csv`: one row per (5-second slot, destination IP) that received
  traffic. `KEY_COLUMNS` followed by `FEATURE_NAMES` from `netsensor/schema.py`.
- `flows.csv`: one row per completed bidirectional flow.
- `stats.json`: schema version and fingerprint, the SHA-256 of each input, and
  counts of every packet that was skipped, repaired, late or malformed.

Only `FEATURE_NAMES` may be given to a model, in that order
(`schema.feature_vector`). Addresses, port values, timestamps and labels are
key columns, never features.

## Build a dataset (D3)

```powershell
.\.venv\Scripts\python.exe -m netsensor build-dataset --plan plan.json [--labels rules.json] --out-dir out\ds1
```

The plan names finished extraction directories (each must have `stats.json`
with input hashes and the current schema fingerprint) and assigns each one to
`train`, `validation` or `test`, either whole or in time blocks. The command
writes `features.csv`, `labels.csv` and `splits.csv`, one row per window in
the same order and keyed by `source_id, window_start_ns, dst_ip`, plus
`manifest.json`. Labels never share a file with features.

- A capture may appear in one source only. Splits are explicit, never a random row shuffle.
- Rows within `purge_seconds` of a change of split are marked `purged`.
  Use at least 180 s: features look back 120 s (flow idle timeout) and 60 s (baseline).
- Infinity fails the build. NaN is kept, and its meaning is documented in `netsensor/dataset.py`.
- Without verified label rules (`labels/README.md`) every row is `unlabelled`
  and the manifest says `usable_for_training: false`.

`netsensor/evaluate.py` holds the metrics: average precision, a threshold for
a false-positive budget fixed on validation, k-of-n alert persistence,
detection delay, and the packets-per-second baseline.

Plans may set `warmup_seconds` (use at least 180). Each source is an
independent extraction that starts with an empty flow table and no baseline,
so its first windows are marked `warmup` and are never used.

## Continuous extraction jobs

```powershell
.\.venv\Scripts\python.exe -m netsensor run-jobs --jobs jobs.json --dry-run   # plan, estimates, preflight
.\.venv\Scripts\python.exe -m netsensor run-jobs --jobs jobs.json [--only g1]
```

Each job is one continuous extraction over an ordered capture range, so flows and
baseline history carry across file boundaries (rotated captures are ordered
numerically: `X_0, X_01, ..., X_09, X_010`). The runner:
- hashes the inputs and records their order before it starts;
- logs per-file time, records, live flows and memory to `progress.jsonl`;
- works in `<id>.attempt-<n>/` and renames to `<id>/` only on success;
- skips completed jobs whose output hashes still verify;
- never overwrites anything;
- stops cleanly when available memory or the process limit is crossed, or when
  a `STOP` file appears in the output root.

See `netsensor/runner.py` for the job-file format.

## Train, score and evaluate (ml-service venv)

```powershell
$py = "..\apps\ml-service\.venv\Scripts\python.exe"
& $py -m netsensor train --dataset DATASET_DIR [--config cfg.json] --out-dir BUNDLE_DIR
& $py -m netsensor predict --bundle BUNDLE_DIR --extraction EXTRACTION_DIR --out-dir OUT
& $py -m netsensor heuristic --extraction EXTRACTION_DIR --out-dir OUT [--threshold-pps 5000 --k 3 --n 3]
```

`train` refuses, with exit code 3 and `training_refused.json`, when any of these hold:
- the dataset is not `usable_for_training` (unverified label rules);
- its `warmup_seconds` is below the 120 s flow timeout;
- a data-sufficiency gate fails: attack or benign windows per split, attack
  episodes, or families.

Otherwise:
- the preprocessor and XGBoost are fitted on the training split only;
- early stopping and the alert threshold (FPR target) use validation only;
- test is scored once;
- the packets-per-second baseline is thresholded the same way and reported
  next to the model (`report.json`, `report.md`, with Wilson intervals).

Recall at an FPR target is reported only when the split has enough benign
windows for that target.

The bundle (never overwritten) holds:
- the model;
- the preprocessing state;
- schema version and fingerprint, feature order;
- threshold and persistence;
- config and seed;
- dataset and label provenance;
- library versions and file hashes.

`netsensor.ml.model.DosDetector` scores one window at a time and rejects
missing, unknown or reordered features, other schema versions, infinity, and NaN
outside the documented nullable features. `PpsHeuristic` is the transparent
demonstration detector (status `HEURISTIC`, not a trained model).
`netsensor.ml.alerts.detection_payload` builds the backend ingest payload;
nothing is sent anywhere.

`predict` and `heuristic` raise **one alert per episode** for each destination: at the
window where the k-of-n rule first holds, not again until it clears. `scores.csv`
keeps per-window `alert` (condition holds) and `raised` columns.

The payload's `riskScore` is a documented severity, not a probability:
`40 + 20*margin + 20*persistence + 20*volume`. Its components, and what the detector's
score means, are in the alert evidence. `confidenceTier` is "likely" only for a trained
model at full persistence and high volume, and never "confirmed". See
`netsensor/ml/alerts.py`.

## Model status (2026-10-18)

| Detector | Status | Why |
|---|---|---|
| XGBoost window model | **TRAINED**: `dos-xgb-99b94241-afefb015` (`C:\datasets\dos-models\dos-xgb-d0311-v1\`) | Verified 03-11 labels. Forward-in-time split: train NETBIOS/LDAP/MSSQL, validation UDP, test SYN (unseen family). The learned model is a single split on `unique_src_ports`, a testbed shortcut (the attacker randomises source ports). Real reflection floods with a fixed source port would likely be missed. There are no confirmed benign windows for the victim, and only one capture day. **Model card: `docs/dos-model-d0311-v1.md`.** |
| pps heuristic | HEURISTIC (demo only) | Threshold 5000 pps, 3 of 3 windows. A stated policy, not tuned on labels; no performance is claimed. |

## Offline demo

```powershell
..\apps\ml-service\.venv\Scripts\python.exe -B demo\offline_demo.py --extraction C:\datasets\netsensor-smoke\run1 --out-dir C:\datasets\dos-demo\NEW_DIR
```

It scores an existing extraction with the heuristic and writes `scores.csv`,
`alerts.jsonl` (one ingest payload per alert episode: `DOS_DDOS`, `PCAP_REPLAY`, `HEURISTIC`) and
`demo_summary.json`. `--export-fixtures` writes the first payload as the
backend/web test fixture; existing fixtures are never overwritten.
