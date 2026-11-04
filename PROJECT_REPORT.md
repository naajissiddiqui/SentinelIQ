# SentinelIQ: full report

Status as of 2026-10-20. More detail: [docs/SUBMISSION.md](docs/SUBMISSION.md) and
[docs/PRESENTATION.md](docs/PRESENTATION.md).

## 1. What SentinelIQ is

SentinelIQ is a security platform with five parts:

1. It detects attacks on a network or on a Windows machine.
2. It shows them to an analyst in a web dashboard.
3. It maps each detection to MITRE ATT&CK, the standard catalogue of attacker techniques.
4. It turns incidents into threat-intelligence (CTI) reports.
5. It anchors each report's fingerprint (a hash of its content) on the Polygon Amoy blockchain, so
   anyone can later check that the report has not been altered.

| Part | Location | What it does |
|---|---|---|
| Network sensor | `sensor/` | Cuts recorded traffic (PCAP files) into 5-second windows of 47 measurements each, scores every window with the network detector, and forwards alerts to the backend. |
| Network DoS model | `C:\datasets\dos-models\dos-xgb-d0311-v1` | Machine-learning detector (gradient-boosted trees) trained on real, labelled CIC-DDoS2019 traffic. |
| Backend | `apps/backend` | Express + MongoDB API. Ingests detections, maps them to MITRE, runs response policies, generates CTI and anchors it on Polygon Amoy. |
| Web app | `apps/web` | Next.js dashboard: detections, evidence, endpoints, CTI, feed and verification. |
| Windows agent | `agent/` | Watches a Windows machine through Sysmon for ransomware and privilege escalation, and can isolate the machine. |
| Smart contract | `blockchain/` | CTIRegistry on Polygon Amoy at `0xAAc39CC2A0B2A37F85bD56421483475c36295beb`. |

### What was built

- **Labelled data and the network model.** Ground-truth labels for CIC-DDoS2019 were verified,
  and the dataset was split forward in time. SYN floods were held out for testing.
- **One alert per sustained attack.** The sensor groups windows into alert episodes. Each carries
  a 0–100 risk score, which is a severity, not a probability.
- **Real ingestion path.** The sensor forwarder (`netsensor ingest-alerts`) and the backend's
  ingestion API store each alert episode only once. `npm run replay:recorded` sends the recorded
  detections into the running app through the real login, endpoint and ingestion APIs.
- **Network DoS safety rule.** Network DoS alerts never isolate machines, never mark them at
  risk, never join cascades and never become CTI. Ransomware handling is unchanged.
- **MITRE with evidence.** Each mapping has a technique ID, name, tactic and the reason it applies.
- **Real data only in ordinary views.** Demonstration and simulated records are kept, but they
  are excluded from lists, counts, the dashboard and CTI. They appear only in an explicit,
  labelled "test records" view.
- **Professional product language.** Labels such as "ML DETECTION", "RECORDED TRAFFIC" and
  "Network DoS"; model details live under "Model information".
- **Removed fake behaviour.** This covered:
  - an isolation that reported success on failure;
  - a sharing toggle and visibility options that saved nothing;
  - a header search and notifications that did nothing;
  - buttons that went nowhere;
  - a fabricated threat-intelligence list;
  - a "CLEAN" result shown on lookup errors;
  - a false SOC 2/SSO claim;
  - invented endpoint values;
  - draft edits that were silently dropped.

  Password change now works, through a new, tested backend route.
- **Blockchain.** One demo report and one corrected revision are anchored on Amoy. Both are shown
  only in the labelled "Demonstration records" view.

## 2. How to run the app

```powershell
cd C:\SentinelIQ
npm run dev:backend      # terminal 1: API on http://localhost:4000 (uses apps/backend/.env: Atlas + Amoy)
npm run dev:web          # terminal 2: web app on http://localhost:3000
```

Sign in at http://localhost:3000 with your account.

To put the recorded network detections into your organisation (terminal 3):

```powershell
npm run replay:recorded -- --email <your sign-in email>
```

The command asks for your password and prints a link for each detection. The first run records
3 detections. Every later run reports them as "already recorded" and creates nothing new.

## 3. How to test the model

### a) Re-run the model on the held-out test traffic

```powershell
cd C:\SentinelIQ\sensor
..\apps\ml-service\.venv\Scripts\python.exe -m netsensor predict `
  --bundle C:\datasets\dos-models\dos-xgb-d0311-v1 `
  --extraction C:\datasets\netsensor-runs\d0311\g5-udplag-syn `
  --out-dir C:\datasets\dos-models\my-rerun      # use a NEW folder name
```

This takes about 5 minutes. It prints `windows 43831, over_threshold 208, alerts 3`, the same
counts as the recorded run.

### b) The official held-out result

The result is already recorded; do not re-run training.

| | |
|---|---|
| Full report | `C:\datasets\dos-models\dos-xgb-d0311-v1\report.md` |
| Summary | `sensor/docs/dos-model-d0311-v1.md` |

On the held-out SYN floods (evaluated once):

| Metric | Result |
|---|---|
| Recall | 1.0 (95% CI 0.959–1.0) |
| False-positive rate | 0.0 |
| False alerts | 0 in 49 benign destination-hours |
| Detection delay | 10 seconds |

### c) Automated tests

```powershell
$env:MONGOD_BIN = "C:\WeddAI\backend\node_modules\.cache\mongodb-memory-server\mongod-x64-win32-7.0.14.exe"
npm run release:check      # stop `npm run dev:web` first: the production build shares apps/web/.next
```

21 of 21 steps pass:

| Step | Result |
|---|---|
| Builds and type checks | pass |
| Web unit tests | 28 tests |
| Web production build | pass |
| Backend unit and local-chain suites | pass |
| Backend database suites (temporary MongoDB, never Atlas) | 10 suites |
| Sensor tests | 136 tests |
| Agent tests | 39 tests |

## 4. How to present (about 8 minutes)

The full script is in [docs/PRESENTATION.md](docs/PRESENTATION.md). In short:

1. **Start the app.** Run `npm run dev:backend` and `npm run dev:web`, then sign in.
2. **Send the detections.** Run `npm run replay:recorded -- --email <you>` and show the output:
   recorded traffic, sent through the real API, with deduplication.
3. **Dashboard.** Active detections, severity, ATT&CK coverage, and Detection Sources (recorded
   traffic versus live telemetry).
4. **Detections, then open one.**
   - Window evidence and capture provenance (files and hashes).
   - T1498 with its reason.
   - No isolation for network DoS.
   - "Model information" holds the model version and score meaning.
5. **CTI Feed, then *Demonstration records*.** The two Amoy-anchored demonstration reports,
   labelled as such; the correction supersedes the original.
6. **Verify Report.** Recompute the hash and compare it with the value on-chain.

Do not claim:

- live traffic, or live Windows monitoring;
- that the risk score is a probability;
- that the demonstration reports are threat intelligence;
- that the network model generalises beyond its testbed.

## 5. Status and limitations

| Area | Status |
|---|---|
| Recorded traffic → API → Atlas → web app | ✅ Verified on the real application (separate verification organisation) |
| Deduplicated replay | ✅ Second run: 0 new, 3 already recorded |
| MITRE with evidence | ✅ |
| CTI lifecycle and blockchain | ✅ On a local test chain; the two existing Amoy transactions are unchanged |
| Generating a genuine CTI report from a real Atlas incident | ❌ Not shown: no eligible real incident exists (network DoS is excluded by design) |
| Live Windows telemetry | ❌ Not verified (Sysmon is not installed) |

Limitations:

1. The network model covers one capture day and one testbed.
2. No threat-intelligence indicator feed is configured (`THREAT_INTEL_IOC_FILE`), so CTI matching
   does not fire.
3. Your Atlas policy "Critical Ransomware Auto-Containment" stores `riskScore >= 0.85`. That came
   from the old editor's wrong scale; edit it to 85 if that was intended. It was not changed.
4. Your Acme organisation's 17 seeded detections are hidden from ordinary views, not deleted.
5. A "SentinelIQ Verification" organisation was created in Atlas for the end-to-end check. It
   holds 1 user, 1 sensor endpoint and 3 detections. It is yours to keep or remove.
