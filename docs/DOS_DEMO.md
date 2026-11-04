# Live DoS/DDoS detection demo (synthetic capture → real model → dashboard)

This runs the **real** SentinelIQ pipeline — the actual sensor, the actual trained model, the actual
forwarder and backend — on a capture you generate on the spot. No fake alerts, no inserting into the
database, no replacing the model.

## Why a synthetic capture (read this first)

The SentinelIQ sensor reads **PCAP files**; it has no live packet capture. Capturing live loopback
traffic on Windows needs Npcap (a kernel driver install). This machine has no Npcap, so the honest,
safe path — and the one the project already supports — is to **generate a real PCAP** of a
DoS pattern and run the real pipeline on it. The generator opens **no sockets and sends nothing on
any network**; it only writes a file. The model's decision on that file is 100% genuine.

So: the **capture is synthetic and processed offline (recorded, not live)**; the **feature
extraction, the model scoring and the detection are real**. Do not describe this as live wire
capture.

## One-time setup

Two terminals for the app (leave running):

```powershell
cd C:\SentinelIQ; npm.cmd run dev:backend      # wait for "Listening on http://localhost:4000"
cd C:\SentinelIQ; npm.cmd run dev:web          # wait for "Ready", then sign in at http://localhost:3000
```

## The demo (about 15 seconds of compute)

```powershell
cd C:\SentinelIQ\sensor
$demo = "C:\SentinelIQ\sensor\dos-demo"
$bundle = "C:\datasets\dos-models\dos-xgb-d0311-v1"   # the existing trained model; not retrained

# 1. Generate a bounded, local-only synthetic DoS capture (10s benign + 20s SYN flood to 127.0.0.1).
.\.venv\Scripts\python.exe -m tools.generate_dos_pcap --out "$demo\dos-local.pcap" `
    --target-ip 127.0.0.1 --target-port 80 --flood-seconds 20 --flood-pps 6000 --benign-seconds 10 --benign-pps 60 --now

# 2. Capture -> windows with the REAL sensor.
.\.venv\Scripts\python.exe -m netsensor extract "$demo\dos-local.pcap" --out-dir "$demo\extract"

# 3. Score every window with the REAL trained model.
..\apps\ml-service\.venv\Scripts\python.exe -m netsensor predict --bundle $bundle `
    --extraction "$demo\extract" --out-dir "$demo\predict" `
    --organization-id 000000000000000000000000 --endpoint-id 000000000000000000000000

# Look at the real scores (benign windows are below threshold, flood windows above):
Get-Content "$demo\predict\scores.csv"
Get-Content "$demo\predict\alerts.jsonl"

# 4. Forward the genuine alert into the running backend as your organization (the real product path).
cd C:\SentinelIQ
npm.cmd run replay:recorded -- --email naajis@acme.com --alerts "C:\SentinelIQ\sensor\dos-demo\predict\alerts.jsonl"
```

It asks for your password (never printed) and prints a link to the detection. Open
**Detections** in the dashboard (or the printed link) and show: attack type **DoS/DDoS**, source
**RECORDED TRAFFIC**, detector **ML DETECTION**, the severity, the window evidence (packet rate,
unique source ports, SYN ratio), the capture timestamp, and the **T1498** MITRE mapping with its
reason.

If step 4 says `already recorded`, the backend already has this exact alert episode (it deduplicates
by endpoint + time + target). Regenerate with a different `--flood-pps` or run the cleanup below to
start fresh.

## Fast presentation mode (no waiting at all)

Run steps 1–3 **before** the professor arrives (they take seconds and write files only). During the
presentation run **only step 4** (the forward), which is instant, then show the dashboard. This does
not falsify anything: the capture and scoring already happened; you are showing the real stored
result. Say so.

## What the professor should take away

- **Traffic generated:** a 30-second local-only capture to `127.0.0.1:80` — a 10s benign segment
  (~20 source ports, normal SYN/SYN-ACK/ACK), then a 20s SYN flood from thousands of distinct
  ephemeral source ports at ~6000 packets/second. Nothing was sent on any network; it is a file.
- **Features observed (per 5-second window, by the real sensor):** inbound packets/second, unique
  source ports, SYN-only ratio, new-flow rate, and more — the `dos-window-v1` schema the model was
  trained on.
- **What the model detected:** the benign windows score **below** its threshold (≈0.475) and are
  **not** flagged; the flood windows score **above** it (≈0.525) and, after the k-of-n persistence
  rule, raise **one** DoS alert. It fired on the **large number of distinct source ports**, which is
  the documented basis of this model.
- **What it proves:** the end-to-end pipeline works — the real sensor extracts the real schema, the
  real trained model discriminates flood from benign on data it has never seen, and the genuine
  alert travels the real forwarder/ingestion path to the dashboard.
- **What it does NOT prove:** this is one synthetic SYN-flood pattern on one testbed. The model keys
  heavily on source-port counts and would likely miss reflection/amplification floods from few
  source ports; it is not validated on real production networks. The capture is recorded, not live.
  See [`sensor/docs/dos-model-d0311-v1.md`](../sensor/docs/dos-model-d0311-v1.md).

## Reset / cleanup

```powershell
Remove-Item -Recurse -Force C:\SentinelIQ\sensor\dos-demo   # remove the generated capture and outputs
```

The demo writes **one** DoS detection to your organization. To remove it, open the detection in the
dashboard and mark it resolved, or delete it directly if you have database access. It is a normal
product record (origin `PCAP_REPLAY`), not production threat data.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `predict` says `alerts: 0` | The flood was too short or too few source ports. Use `--flood-seconds 20` or more and `--flood-pps 6000`; the flood must exceed 511 unique source ports across 3 consecutive windows. |
| Forward says `already_recorded` | The backend deduplicates this alert episode. Regenerate with a different rate, or clean up and re-forward. |
| Alert not on the dashboard | Hard-refresh (Ctrl+F5). Confirm the forward printed `created: 1`. Confirm you signed in as the same organization you forwarded to. |
| `extract` errors on the pcap | Regenerate the capture; do not hand-edit the `.pcap`. |
| Forward refuses the target | The forwarder only sends to a local backend (`127.0.0.1`/`localhost`) unless `--allow-remote` is given. |

## Tests

```powershell
cd C:\SentinelIQ\sensor
.\.venv\Scripts\python.exe -m unittest tests.test_generate_dos_pcap      # generator is local-only, bounded, opens no socket
.\.venv\Scripts\python.exe -m unittest tests.test_ingest                 # the alert forwarder / ingestion path
```
