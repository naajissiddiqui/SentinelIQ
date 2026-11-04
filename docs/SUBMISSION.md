# SentinelIQ: submission package

Status as verified on 2026-10-20. A claim appears here only if it was run or observed. Anything
not verified says so.

## Run the application

| Goal | Command |
|---|---|
| Real application (your `.env`: Atlas + Polygon Amoy) | `npm run dev:backend` and `npm run dev:web` |
| Send the recorded network detections into it | `npm run replay:recorded -- --email <your sign-in email>` |
| Every build, type check and test suite (disposable DB) | `$env:MONGOD_BIN="C:\path\to\mongod.exe"; npm run release:check` |
| Isolated rehearsal copy (disposable DB) | `$env:MONGOD_BIN="C:\path\to\mongod.exe"; npm run demo` |

The step-by-step presentation is in [PRESENTATION.md](PRESENTATION.md).

## What was verified on the real application (2026-10-20)

The real backend (`npm run dev:backend`, connected to the configured Atlas database) and the real
web app (`npm run dev:web`) were used.

**Ingestion through the real path.** A new organisation, "SentinelIQ Verification", was
registered through `POST /auth/register`. No existing record was read for it or changed.
`npm run replay:recorded` then:

- signed in through the real login API;
- registered the endpoint "Network Sensor (recorded traffic)";
- forwarded the three recorded alert episodes with `python -m netsensor ingest-alerts`.

**Results.**

- First run: 3 newly recorded.
- Second run: 0 new and 3 already recorded, with the same detection IDs (server-side
  deduplication).

**Browser check.** Headless Chromium on `http://localhost:3000`, signed in through the real login
form, passed 26 checks. Screenshots are in [screenshots/](screenshots/).

| Page | What was checked |
|---|---|
| Dashboard ([dashboard.png](screenshots/dashboard.png)) | 3 active detections; Detection Sources shows "Recorded traffic 3"; ATT&CK shows "T1498 Network Denial of Service · Impact 3" |
| Detections ([detections.png](screenshots/detections.png)) | 3 rows labelled Network DoS · RECORDED TRAFFIC · ML DETECTION, with the original 2018 capture dates |
| Detection detail ([detection-detail.png](screenshots/detection-detail.png)) | "Traffic captured … analysed from a recording"; window evidence; capture provenance (10 files with hashes); T1498 with its reason; no CTI action for network DoS |
| Model information ([detection-detail-model-info.png](screenshots/detection-detail-model-info.png)) | Model version and score semantics, shown only when expanded |
| CTI Feed ([cti-feed.png](screenshots/cti-feed.png), [cti-feed-demonstration.png](screenshots/cti-feed-demonstration.png)) | No demonstration report in the default feed. The "Demonstration records" view shows the two Amoy-anchored demo reports, labelled, with the original marked as superseded |
| Threat Intel ([threat-intel.png](screenshots/threat-intel.png)) | States honestly that no indicator feed is configured |
| CTI Center | Honest empty state; "Go to Detections" now navigates |
| Settings | The fake sharing toggle is replaced by an accurate statement |

Every page was also scanned for internal terms (XGBoost/XGB, heuristic, PCAP, DEMO DATA, [DEMO],
mock, seeded, RansomShield); none appeared.

**Atlas afterwards (read-only check).** Every pre-existing organisation, endpoint, detection and
CTI report is unchanged. The only additions belong to the verification organisation:

- 1 organisation and 1 user, with its login sessions;
- 1 endpoint;
- 3 detections, with their timeline and audit entries.

## Why the prepared detection did not appear before

Atlas held no network (DoS) detection at all. Every earlier ingestion of the recorded alerts had
gone to disposable test databases (`npm run demo` and the end-to-end tests), never to the backend
the real web app uses. Two further gaps made a real run awkward:

- There was no command that signs in, finds the organisation's sensor endpoint and forwards the
  alerts.
- The forwarder refused to run twice, while the backend had no deduplication.

`npm run replay:recorded` and server-side episode deduplication close both gaps.

## Changes in this pass (summary)

- **Test records are not incidents.** Demonstration data (`DEMO`, `DEMO-*` rules or models) and
  simulated telemetry (`SIMULATED`) are excluded from detection lists, counts, the dashboard and
  CTI lists by default (`scope=incidents`). They stay stored, unmodified, and available through
  an explicit, labelled view (`scope=test`).
- **Ingest deduplication.** A sensor alert episode has a key made of endpoint, origin, type,
  rule, model, time and target. Re-sending it returns the stored detection with HTTP 200 and
  `duplicate: true`.
- **Professional wording.** The algorithm name is no longer a user-facing label. The UI uses
  "ML DETECTION", "Machine-learning network detector", "RECORDED TRAFFIC", "LIVE TELEMETRY" and
  "Network DoS". Model details are under "Model information".
- **Fake UI removed or fixed:**
  - Endpoint isolation used to show success when the request failed.
  - "Invitation sent" claimed an email that is never sent.
  - The CTI visibility and sharing toggles did nothing.
  - The header search, bell and workspace menu did nothing.
  - "View Endpoint", "Go to Detections" and the other `navigate()` buttons went nowhere.
  - A failed threat-intel lookup was shown as "CLEAN".
  - The login page claimed "SSO available · SOC 2 Type II".
  - Endpoint OS and resource values were invented.
  - "Quick verify" did not verify.
  - IOC and recommended-action edits on CTI drafts were silently dropped.
  - The password-change form had no backend route; it now has a real, tested one.
- **Fabricated threat intelligence removed.** The built-in IOC list (documentation-range IPs,
  example.com domains, invented feed names) is now a test fixture. In production, indicators load
  only from `THREAT_INTEL_IOC_FILE`, and the UI says when none are configured.
- **Policy editor scale.** Risk score is entered on its real 0–100 scale; it used to say
  0.0–1.0 with a default of 0.85.

## Test evidence (`npm run release:check`, 21 of 21 steps passed)

| Step | Result |
|---|---|
| shared-types build, backend `tsc`, web `tsc` | pass |
| Web unit tests | 28/28 |
| Web production build (`next build`) | pass |
| Backend unit (`cti_anchor.unit`, `dos_ddos.unit` 16/16, `mitre_and_cti`) | pass |
| Backend local Hardhat chain (`cti_anchor.localchain`) | pass |
| Backend suites on a disposable MongoDB (10, including the new `auth-password.db`) | all pass |
| Sensor (`unittest`, including ML) | 136 OK |
| Agent (`unittest`) | 39 OK |

## Component status

- **Network DoS detection.** Model `dos-xgb-99b94241-afefb015`, a gradient-boosted tree model.
  On the held-out SYN test, evaluated once:
  - recall 1.0 (95% CI 0.959–1.0);
  - FPR 0.0;
  - 0 false alerts in 49 benign destination-hours.

  Limitations are in [the model doc](../sensor/docs/dos-model-d0311-v1.md): one testbed, a
  source-port-count shortcut, and an unmeasured victim false-alert rate. The model and its
  evaluation were not changed.
- **MITRE.** Mappings come from detection evidence, each with a stated reason. Types without
  evidence stay unmapped.
- **CTI.** The full lifecycle was verified on a local chain. Network DoS alerts are refused CTI
  (422). Your organisation has no eligible real incident, so generating a genuine CTI report from a
  real detection was **not** demonstrated on Atlas.
- **Blockchain.** The two existing Amoy transactions (`0x9721610b…886c` and the correction
  `0x1ae44049…82427`) are unchanged. No transaction was sent in this pass.
- **Windows endpoint telemetry.** The agent and its tests pass. Live Sysmon ingestion is **not
  verified**, because Sysmon is not installed here.

## Known limitations

1. Live Windows telemetry is unverified.
2. The network model covers one capture day and one testbed.
3. No threat-intelligence indicator feed is configured. CTI matching therefore never fires until
   `THREAT_INTEL_IOC_FILE` is set.
4. Your Atlas policy "Critical Ransomware Auto-Containment" stores `riskScore >= 0.85` from the
   old editor. Against the real 0–100 scale it matches almost every score. It was not changed;
   edit it to 85 if that was the intent.
5. Your Acme Corp organisation's 17 seeded detections are hidden from ordinary views, not deleted.
6. Report verification is scoped to the organisation that owns the report. Verifying the two demo
   reports needs the Acme account; it was not exercised in the browser in this pass.
