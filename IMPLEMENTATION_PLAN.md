# SentinelIQ — Implementation Plan: ML Ransomware + DoS/DDoS Detection

*This is a proposal for review. No application code was changed.*

## 1. Executive Summary

SentinelIQ's **architecture** is reusable as it stands. It has:

- a Sysmon-based Windows agent
- per-process 10 s feature windows
- an XGBoost scorer
- a Node/Mongo backend with policies and correlation
- a Next.js dashboard
- a CTI/Polygon Amoy anchoring path

The **ML evidence is not credible yet**:

- The training data can be separated by a trivial rule, which is why the reported metrics are perfect.
- The training script cannot be reproduced.
- The live Sysmon reader drops events during bursts.
- Current demos run on `TELEMETRY_MODE=simulated` (set in `agent/.env` and `.env.agent1–3`).

The plan, in priority order:

1. **Make ransomware detection trustworthy.** Fix ingestion, record real Windows telemetry, rebuild the dataset, retrain with a leakage-safe evaluation, and add EVTX replay so live and recorded data run through the same code.
2. **Add a separate DoS/DDoS pipeline** (approved 2026-10-17, see §4). A new top-level `sensor/` package processes recorded PCAPs offline. It classifies 5-second per-destination windows with XGBoost, compared against a packets-per-second baseline, and is trained and evaluated on the public CIC-DDoS2019 and CIC-IDS2017 datasets. It reports through the existing ingest API as an alert-only `DOS_DDOS` detection.
3. **Retire privilege escalation (PE)** by refactoring it out step by step after review.
4. **Validate with public datasets, replay, controlled lab tests and live benign observation**, not with custom simulators.

## 2. Current Architecture and Codebase Audit

**Audit method:** I read the source; nothing was executed. The working tree has **82 uncommitted or untracked changes**, including `agent/privilege_escalation.py`, `windows_event_reader.py`, `mitre_mapper.py` and `agent/dos/`. The audit reflects the working tree, not `HEAD`.

| Component | Location | What the code does |
|---|---|---|
| Agent loop | `agent/agent.py` (`Agent._poll`, `_score_window`, `run`) | Polls every 3 s. Buffers events per PID in 10 s windows (`sliding_window_buffer.py`). Skips windows with fewer than 3 events and process names on `WHITELIST`. |
| Telemetry | `sysmon_reader.py`, `telemetry_provider.py`, `sysmon/sysmonconfig.xml` | Real mode uses `WindowsTelemetryProvider` → `SysmonReader.read_latest`. `SimulatedTelemetryProvider` has `normal`, `ransomware` and `privilege_escalation` scenarios. |
| Features | `feature_extractor.py` (`FeatureExtractor.extract`) | 21 features: counts of Sysmon event IDs 1/2/3/5/11/13/17/22, rates, extension and directory counts, filename-string entropy, path statistics. |
| Agent model | `agent/models/ransomware_xgb.json`, `models/train_model.py` | Local XGBoost. EMA smoothing with α = 0.4. Thresholds 0.50/0.65; CRITICAL after 3 consecutive windows. Only CRITICAL is reported (`_report_ransomware_alert`). |
| ML service | `apps/ml-service` (`/predict/`, `train_model.py`, `model.pkl`) | A **separate** model that picks RF or XGB. `model_metadata.json` reports **ROC-AUC 1.0, F1 1.0**. **The agent never calls it** (`ml_client.get_prediction` is unused). |
| Ingest | `controllers/detection.controller.ts` → `services/detection.service.ts` (`createDetection`) | Runs CTI IOC matching and saves the Detection. Sets the endpoint to `AT_RISK`, writes the timeline and emits a Socket.IO event. Then runs `correlateCascade` and `evaluatePolicies`, except for PE detections, which return before those steps. |
| Schema | `models/detection.model.ts`, `packages/shared-types/src/enums.ts` | Has `attackType`, `ruleId`, `confidenceTier`, `riskScore`, `evidence[]` and `mitre[]`. `AttackType` = RANSOMWARE / PRIVILEGE_ESCALATION / DATA_EXFILTRATION. |
| Policies | `models/policy.model.ts`, `services/policy.service.ts` | Actions are `ISOLATE_ENDPOINT`, `CREATE_ALERT` and `MARK_HIGH_RISK`. A `detectionType` condition exists, but **`createDetection` never passes `detectionType`**, so that condition never matches. |
| Correlation | `services/cascade.service.ts` | Correlates across endpoints within 120 s. **Does not filter by `attackType`.** Its cascade types are ransomware/C2-specific. |
| Isolation | `agent/isolation_provider.py` | Both providers **only set internal state**. Nothing is enforced on the network or on processes. |
| CTI/chain | `cti.service.ts`, `ctiAnchor.service.ts`, `blockchain.service.ts`, `CTIRegistry.sol` | Drafts are created, published and anchored on Amoy. Unit and local-chain tests exist. **Live Amoy publication was not verified.** |
| Dashboard | `apps/web/src` (`AppProvider.tsx`, `app/detections`, `app/dashboard`) | Live via Socket.IO. The detection list filters by status but **not by attack type**. |
| DoS stub | `agent/dos/features.py` | Schema for **service metrics** (request rate, latency, CPU) with `add_baseline_features`. The generator and collector it mentions **do not exist**. |

### Critical findings

1. **The dataset is not credible.** `agent/dataset/RANSOMWARE.csv` has 20,000 rows (10k ransomware, 10k benign):
   - Every ransomware row has zero process, network, DNS and registry activity.
   - `known_encrypted_ext_count > 0` appears *only* in ransomware rows.
   - 149 rows are duplicates.
   - Its origin is unknown.

   One trivial rule separates the classes, which explains the 1.0 metrics.
2. **The model cannot be reproduced.** `agent/models/train_model.py` reads `dataset/ransomware_v3.csv`, which is not in the repo. It also uses a random row split. Overlapping windows from the same run then land in both train and test, which leaks information.
3. **The live reader loses events.** `SysmonReader.read_latest` reads newest-first and returns **at most 64 events per 3 s poll**. During an encryption burst, most file events are dropped.
4. **Live features may not match training features.** `sysmonconfig.xml` only has rules for event IDs 1, 11 and 13 (registry limited to `Run`/`Services`). Whether 2/3/5/17/22 are emitted depends on Sysmon defaults (*open question*). If event 3 is absent live, every process shows `network_connection_count = 0`, which is exactly the ransomware shortcut in the training data.
5. **Feature semantics are weak:**
   - "Entropy" is measured on the filename string, not file content.
   - Rates always divide by 10 s.
   - `\documents\` and `\desktop\` count as "suspicious" paths.
   - There are no file-delete or shadow-copy features.
6. **There is a data-collection bug.** `CSVLogger` only writes the last `result` variable every third step, and raises `NameError` if no window was scored.
7. **Alerts carry thin evidence.** `confidenceTier` is hard-coded to `"confirmed"` and `modelVersion` to `"xgboost-v1.0.0"`. No feature values are sent.
8. **Documentation is stale:**
   - `README.md` is wrapped in a PowerShell `@'…'@ | Set-Content` command, and its metrics (0.9956/0.9614) disagree with the model metadata.
   - `MULTI_THREAT_IMPLEMENTATION_PLAN.md` was written without access to the repo. This plan supersedes it.

## 3. Proposed Ransomware ML Improvements

**3.1 One feature/model contract**
- Create `agent/features/ransomware_v2.py`, which owns `FEATURE_NAMES` and `SCHEMA_VERSION`. The agent, the training code and the ML-service schema all import it.
- Save the model together with metadata: feature order, schema hash, training-data hash, threshold and metrics. The agent refuses to load a model whose schema doesn't match.
- Keep inference **local in the agent**, since it already works offline. Either make `apps/ml-service` load the same artifact for batch scoring, or retire it (*decision needed*).

**3.2 Telemetry fixes (before collecting any data)**
- Replace `read_latest` with a forward, bookmarked read (`EventRecordID > last`) that drains the log on each poll. Add counters for events read, events dropped and lag.
- Add an **`EvtxReplayProvider`** that reads `.evtx` files and uses event timestamps. Live, recorded and public data then share the same `_poll → buffer → extract` path.
- In `sysmonconfig.xml`, explicitly enable event IDs 1, 2, 3, 5, 11, 22 and **26 (FileDeleteDetected)**. Record the Sysmon version and config hash with every recording.
- Fix `CSVLogger` so it logs every window, with `session_id` and `host` columns.

**3.3 Feature v2 additions (from Sysmon fields only)**
- **File events:** deletes per second, the share of new extensions per directory, and identical filenames created in N or more directories (ransom notes).
- **Command lines:** `vssadmin delete shadows`, `wbadmin delete`, `bcdedit … recoveryenabled no`, and `wmic shadowcopy delete` (T1490).
- **Process tree:** child-process fan-out.
- **Shortcut features:** demote or remove the `network_*` shortcut features, and report ablations with and without `known_encrypted_ext_count`.
- **Out of scope:** file-content entropy, which needs a minifilter or ETW.

**3.4 Labelling and leakage control**
- Label windows from **session ground truth**, meaning the documented malicious image or PID and its time range, never from model scores.
- Use `GroupKFold` grouped by session, host and sample family, plus a final test set held out by time.
- Include hard negatives in the benign data: archivers encrypting our own files, backup and sync clients, builds, Windows Update and bulk copies.

**3.5 Metrics**
- **Window level:** PR-AUC, and recall at a fixed false-positive rate.
- **Incident level:** detection rate, **time-to-detect**, and files touched before the alert.
- **Operational:** **false alerts per endpoint-day** on live benign recordings.
- Calibrate the EMA, threshold and persistence settings on a validation split, and store the chosen values in the model metadata.

**3.6 Alert payload**
- `_report_ransomware_alert` sends the top feature values and their contributions, the window range, and the schema and model versions taken from metadata.
- The confidence tier comes from score bands instead of being hard-coded.
- MITRE mapping: T1486, plus T1490 when command-line indicators fire.

## 4. Proposed DoS/DDoS ML Pipeline

**4.1 Why it needs its own pipeline.** Sysmon event 3 logs one record per connection, with no byte or packet counts. That cannot detect floods. DoS detection needs **flow telemetry** collected at the protected server or the lab gateway.

**4.2 Approved decisions (2026-10-17)**

| Decision | Detail |
|---|---|
| Location | A separate top-level `sensor/` Python package with its own venv. It is not part of `agent/` or the Sysmon/ransomware path. `agent/dos/features.py` (a service-metrics stub for a synthetic generator that was never built) is left untouched and unused. |
| First mode | **Offline PCAP processing only**, with packet timestamps taken from the capture. Live interface capture and `tcpreplay` are **out of scope**. |
| Unit of classification | **5-second windows per destination IP**, aligned to the epoch grid of packet time. |
| Model | **XGBoost** as the primary model, always compared against a **packets-per-second threshold baseline** on the same windows and at the same false-positive rate. A flow-level model is an optional later ablation. |
| Labels | Ground truth comes from versioned per-dataset label-rule files and is joined to predictions only **after** scoring. The scorer never reads labels; a test proves scores are identical with the label file absent. |
| Ransomware | The ransomware pipeline is not modified. |
| Response | **Alert-only.** No mitigation, no endpoint isolation and no claim of either. |
| CTI | DoS CTI drafts are **not generated yet**. The backend answers a deliberate "unsupported operation" response for them. |

**4.3 Sensor and feature schema**
- **One schema module** (`sensor/netsensor/schema.py`) is imported by both training and inference. It defines the schema version, `WINDOW_SECONDS`, the ordered feature list, the key columns (kept apart from the features) and a denylist.
- **Extraction:** a standard-library PCAP/pcapng reader → link-layer/IPv4/IPv6 decoder → bidirectional flow table (idle 120 s, active 300 s, FIN/RST with a 1 s linger, flows open at EOF flagged incomplete) → per-destination window aggregator. One extractor serves training and inference. Flows are regenerated from the dataset PCAPs rather than taken from the published CICFlowMeter CSVs; the CSVs are used only to cross-check our labels.
- **Window features:** inbound/outbound packets and bytes and their rates; packet-length mean/std/min/max/p50/p95; inter-arrival mean/std/min/max/CV; protocol shares; fragment share; TCP flag ratios (SYN-only, SYN-ACK reply ratio, RST, FIN, PSH, ACK-only); unique sources, unique source prefixes, normalised source entropy, top-source share; unique source/destination port **counts**; per-window flow statistics (active, new, packets/bytes per flow, single-packet share, unanswered share); baseline ratios against the previous 12 windows.
- **Never features:** IP addresses, port values, timestamps, flow IDs, TTL, IP ID, TCP initial window, MAC addresses, payload and dataset labels. These are used for grouping and labelling only. Port **counts** are allowed but will be ablated.

**4.3b Model**
- XGBoost on window features, with thresholds fixed on validation and a k-of-n persistence rule for alerts.
- The packets-per-second baseline is reported alongside it at the same FPR. If XGBoost does not beat it, that is reported as found.

**4.4 Datasets**

| Dataset | Use | Limitations |
|---|---|---|
| **CIC-DDoS2019** | Main training data: reflection and flood DDoS (DNS, LDAP, NTP, SSDP, UDP, SYN, …) | Very few benign flows; CICFlowMeter artefacts; mostly reflection attacks. Use its **training-day / test-day** split, not a random split. |
| **CIC-IDS2017** (DoS/DDoS days) | Application-layer DoS (Hulk, GoldenEye, Slowloris); **cross-dataset test** | Documented labelling and flow errors; evaluate the corrected relabelled version too. |
| **Own lab benign captures** | Benign traffic for the target server; false-positive measurement | Small; lab-only traffic. |

Download the datasets manually and only after approval. Check the licence and disk space first, because the PCAPs are large.

**4.5 Evaluation**
- Per flow and per window: PR-AUC and recall at a fixed false-positive rate, broken down by attack family.
- Detection delay, and false alerts per hour on benign traffic.
- Train-2019 → test-2017 generalisation, reported honestly.

**4.6 Integration**
- The sensor posts to `/api/detections/ingest` with:
  - `attackType: "DOS_DDOS"`, `ruleId: "DOS-XGB"`, a new `dataOrigin` field (`LIVE` | `PCAP_REPLAY`), and `riskScore` = 100 × the calibrated window score
  - a confidence tier of `likely` or `suspicious` only; the model alone never claims `confirmed`
  - evidence: target, capture window, prediction (score, threshold, model and schema version), top feature values, protocol mix, PCAP provenance, and — on replay only — a separate dataset-label block
  - MITRE T1498 by default. Sub-techniques are added only from evidence the model saw, never from the dataset label.
- A "Network Sensor (PCAP replay)" endpoint is registered through the existing activation flow. A DoS detection does not set it to `AT_RISK`.
- The dashboard shows a **PCAP REPLAY** badge. Replay is never presented as a live attack.

## 5. Real Telemetry and Validation Strategy

| Category | Ransomware | DoS/DDoS | What it proves |
|---|---|---|---|
| **Recorded datasets** (offline) | Public Sysmon EVTX. Candidates to vet for coverage and licence: Splunk `attack_data` (T1486/T1490), OTRF Security-Datasets, EVTX-ATTACK-SAMPLES | CIC-DDoS2019, CIC-IDS2017 | Accuracy against third-party ground truth |
| **Offline replay** | `EvtxReplayProvider` → agent → backend → dashboard | Dataset PCAP **file** read offline by `sensor/` (packet-time pacing; nothing is transmitted on any network) → backend → dashboard, badged PCAP REPLAY | The full pipeline works on real recorded traffic |
| **Controlled testing** | Atomic Red Team T1486/T1490 tests on our own dummy data (check which Windows atomics exist); encryption/archive tools run as hard negatives | **None.** No attack traffic is generated or executed. | — |
| **Live observation** | Several days of benign monitoring on team machines | Out of scope (live capture is not built yet) | **False-positive rate** in real use |

**Safety rules**
- Never download or run malware automatically.
- Detonation happens only with written supervisor approval, performed by an authorised person in an offline, snapshot-reverted VM. Export the EVTX before reverting.
- Write no attack tooling, and keep all traffic inside the isolated network.
- `generate_ransomware_behavior.py` and `agent/simulator/*` remain smoke tests only. They are **never** training or validation evidence.

**Caveat:** public EVTX files were recorded with other Sysmon configurations. Record which event IDs each source contains, and evaluate only on the features those IDs support.

**Demo:**
1. Metrics on held-out public data.
2. Replay of a recorded ransomware EVTX, and offline processing of a labelled DoS PCAP, into the dashboard. Both are labelled as replay, never as live.
3. False-positive statistics from live benign monitoring.

Each item is labelled with its validation category.

## 6. Integration Changes and Privilege Escalation Removal

**Backend**
- Add `DOS_DDOS` to `AttackType` and validate `attackType`/`confidenceTier` in `ingestDetection`.
- Pass `detectionType: attackType` to `evaluatePolicies`.
- Restrict `correlateCascade` to ransomware.
- Make the timeline and status text depend on attack type (`detection.service.ts`).
- For `DOS_DDOS`: skip `correlateCascade` and the `AT_RISK` change; add a `DOS-XGB` → T1498 entry to `utils/mitre.ts`, because unknown types currently fall back to the ransomware mapping (T1486).
- `generateCTIDraft` refuses `DOS_DDOS` detections with a deliberate unsupported-operation response. No DoS CTI drafts are created yet.

**Policies**
- Ransomware policies may use `ISOLATE_ENDPOINT`.
- DoS is **alert-only**. A hard guard stops `ISOLATE_ENDPOINT` for any non-ransomware detection. A DoS detection matches only a policy with an explicit `detectionType = DOS_DDOS` condition, and then only `CREATE_ALERT`/`MARK_HIGH_RISK`. No mitigation is implemented or claimed.
- State clearly that isolation is currently state-only. Real enforcement is future work and needs approval.

**Dashboard**
- Attack-type filter and badges in `app/detections/page.tsx`.
- DoS evidence panel in `app/detections/[id]/page.tsx`: pps/bps against baseline (Recharts is already present), top sources, protocol mix.
- Per-type counts on the dashboard.
- Model and schema version on the detail view.

**PE code to refactor (nothing removed now)**
- **Agent:** `privilege_escalation.py` and `windows_event_reader.py`. In `agent.py`: `pe_detector`, `event_log_reader`, `_handle_pe_alert`, `_report_pe_alert` and the `privilege_escalation` scenario. Also the PE scenario in `telemetry_provider.py`, the `PE-*` entries in `mitre_mapper.py`, and `tests/test_privilege_escalation.py` and `tests/test_privesc_simulation.py`.
- **Backend:** PE branches in `detection.service.ts` and `cti.service.ts`, the `PE-*` map in `utils/mitre.ts`, and the enum values.
- **Web:** `components/PrivilegeEscalationAlert.tsx`, `lib/alertSummary.ts` (and its test), and the PE conditionals in `detections/[id]`, `cti-draft-editor`, `cti-feed` and the endpoint pages.
- **Approach:** put PE behind a disabled `ENABLE_PE` flag, make the code generic, then delete the PE code after review.
- **Caution:** `utils/canonical.ts` defaults the detector id to `"PE-01"`. Changing it changes the hashes of reports that are already anchored, so keep it. Existing PE records stay in Mongo and are shown as "legacy".

## 7. Phased Implementation Roadmap and Acceptance Criteria

| Phase | Work | Key files | Acceptance criteria |
|---|---|---|---|
| **P0 Baseline** | Tag the current tree, run the existing tests, record the Sysmon version and config, fix README | `README.md`, `agent/tests/`, `apps/backend/src/tests/` | Test results recorded; §8 questions assigned |
| **P1 Telemetry** | Bookmarked reader, drop counters, `EvtxReplayProvider`, Sysmon config, `CSVLogger` fix | `sysmon_reader.py`, `telemetry_provider.py`, `agent.py`, `sysmonconfig.xml` | Zero dropped events during a 1,000-file benign bulk copy; replaying the exported EVTX gives the same feature vectors as live (unit test) |
| **P2 Ransomware v2** | Benign recordings, approved public EVTX, feature v2, grouped splits, training with metadata | `agent/features/`, `agent/models/train_model.py`, `agent/data/README.md` | Training reproducible from documented data; held-out-session metrics, ablations and a model card; benign false alerts meet the agreed target (proposed ≤ 1 per endpoint-day) |
| **P3 Ransomware integration** | Evidence payload, confidence tier, schema check, `detectionType` passed to policies, UI filter | `agent.py`, `detection.service.ts`, `policy.service.ts`, web pages | Replay demo shows feature evidence; backend test shows a `detectionType` policy firing |
| **P4 PE removal** | Flag → refactor → delete after approval | §6 list | Tests pass with PE off; legacy PE records still display |
| **P5 DoS/DDoS** | Phases D1–D8 below | `sensor/` | See D1–D8 |
| **P7 Validation** | Run the §5 matrix and package the results | `docs/validation/` | Every demo claim maps to a labelled evidence category |

**DoS/DDoS sub-phases (P5)**

| Phase | Work | Acceptance criteria |
|---|---|---|
| **D1 Data manifest** (needs the manual downloads) | Dataset manifest (URL, date, terms, SHA-256 per file); label-rule files | Every file hashed; label agreement with the official CSVs measured and reported |
| **D2 Extractor** | `sensor/`: PCAP/pcapng reader, IPv4/IPv6 decoder, bidirectional flow table, 5 s window aggregator, shared schema module, unit tests on hand-built benign packets | Malformed input, fragments, empty captures and incomplete flows handled explicitly and tested; same input gives byte-identical output; features invariant to IP/port/timestamp relabelling; throughput measured (not assumed) |
| **D3 Dataset build** | Window tables with a split column | No capture file in two splits; duplicate and overlap report |
| **D4 Train and evaluate** | pps baseline and XGBoost; metadata, metrics and a model card | Reproducible metrics; single-feature AUC audit; ablations |
| **D5 Replay runner** | Offline scoring of a PCAP; separate `annotate` step for labels | Scores identical with the labels file absent |
| **D6 Backend** | §4.6 and §6 changes | Tests: no cascade, no isolation, no T1486 and no CTI draft for DoS |
| **D7 Dashboard** | Filter, PCAP REPLAY badge, DoS evidence panel | Ransomware views unchanged |
| **D8 Demo bundle** | Provenance, metrics, replay run log | Every claim tagged offline evaluation / PCAP replay / live |

**Dependencies:** P1 → P2 → P3 is the critical path. D2 can start now; D3 onwards needs D1's datasets. D6 should land with or after the P3 `detectionType` fix. P4 can run any time after P3.

## 8. Risks, Limitations, and Dependencies

**Risks**
- **Little real ransomware telemetry exists.** Public Sysmon ransomware EVTX is scarce and recorded under other configurations. *Mitigation:* combine several sources and add Atomic Red Team tests. State the limitation openly, and never use synthetic data as a substitute.
- **Window metrics can hide incident-level false positives.** *Mitigation:* gate acceptance on false alerts per endpoint-day.
- **DoS train/serve skew.** *Mitigation:* use one extractor for training and live traffic.
- **CIC-DDoS2019 imbalance and artefacts.** *Mitigation:* day-based split, cross-dataset test, class weights.
- **Environment dependencies.** Sysmon volume and agent CPU once every event is read (measure in P1); disk space for the dataset PCAPs (about 200 GB budgeted) and the throughput of a pure-Python PCAP parser (to be measured in D2/D3); live capture (Npcap plus admin rights) only if it is ever brought into scope; Amoy RPC and funding availability.

**Limitations**
- No file-content entropy.
- Isolation is state-only.
- The DoS detector only sees traffic that reaches the sensor.

**Open questions**
1. Where did `RANSOMWARE.csv` come from, and where is `ransomware_v3.csv`?
2. Which Sysmon version and config run on the demo hosts (`sysmon -c`)?
3. Has Amoy publication ever succeeded end to end? `scripts/blockchain-status.ts` exists but was not run.
4. Will the supervisor approve sandbox detonation, or only third-party EVTX?
5. Which lab machines and isolated network are available, and what is the DoS target service?
6. Should `apps/ml-service` be kept or retired?
7. What false-positive targets should acceptance use?
