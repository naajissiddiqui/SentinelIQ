# Live DoS/DDoS monitoring (continuous capture → trained model → dashboard)

This runs the **real** SentinelIQ pipeline continuously on **live packets** from a network
interface: capture → the same rolling-window feature extraction as offline → the same trained
`dos-xgb-d0311-v1` model → the same persistence rule → the same backend ingestion, with every alert
labelled **`dataOrigin: LIVE`**. No synthetic packets, no PCAP replay, no fabricated detections.

## What needs your machine (prerequisites)

The sensor captures via **Npcap + scapy**, which this development machine does not have. The
capture code and the entire pipeline are implemented and tested (see "Verified" below); the actual
NIC binding needs these on the machine that will monitor:

1. **Install Npcap** — https://npcap.com — during install **check "Install Npcap in WinPcap
   API-compatible Mode"**. (Npcap is a signed kernel driver; install it yourself, don't let any
   script install drivers.)
2. **Install scapy into the ml-service venv** (this venv has both scapy and the model libraries, so
   all `netsensor live` commands use it — the sensor `.venv` is standard-library only):
   ```powershell
   C:\SentinelIQ\apps\ml-service\.venv\Scripts\python.exe -m pip install scapy
   ```
   (On this machine scapy is already installed there.)
3. **Run the sensor from an Administrator PowerShell** — live capture needs elevation.

> All `netsensor live` commands below use `..\apps\ml-service\.venv\Scripts\python.exe`. Running
> them with the sensor `.venv` fails with "needs numpy/scikit-learn/xgboost".

Capture only interfaces on systems **you are authorized to monitor**. This tool only observes; it
never generates traffic and never isolates an endpoint.

## Start the stack

```powershell
cd C:\SentinelIQ; npm.cmd run dev:backend      # wait for "Listening on http://localhost:4000"
cd C:\SentinelIQ; npm.cmd run dev:web          # http://localhost:3000, then sign in
```

In the dashboard, **Endpoints → Add Endpoint**, name it e.g. `Live Network Sensor`, and note its
**endpoint id** (open the endpoint; the id is in the URL) and your **organization id**.

## Pick the interface, then VERIFY capture actually works

```powershell
cd C:\SentinelIQ\sensor
..\apps\ml-service\.venv\Scripts\python.exe -m netsensor live --list-interfaces
```

It prints the capture interfaces (e.g. `\Device\NPF_{...}`). **Important: listing interfaces works
even without Npcap and does NOT prove capture works.** If you also see
`WARNING: No libpcap provider available ! pcap won't be used`, Npcap is **not installed** and capture
will see zero packets — finish the prerequisites above.

**Always verify the capture path with the bounded smoke test before live detection.** It opens one
interface for a few seconds, counts packets, and exits. It runs no model, forwards nothing, and
generates no traffic:

```powershell
..\apps\ml-service\.venv\Scripts\python.exe -m netsensor live --smoke-test --interface "\Device\NPF_{YOUR-GUID}" --seconds 5
```

- Success: `{"interface": "...", "seconds": 5.0, "packets": 1234, "bytes": ..., "capturing": true}`.
  Generate a little traffic (open a web page) during the 5 seconds so there is something to see.
- If it exits with Npcap instructions, capture is not available yet — install Npcap and retry.
- If `capturing` is `false` with zero packets, the interface is wrong or idle; pick the adapter
  carrying your traffic.

Only proceed to live monitoring once the smoke test shows `capturing: true`.

## Start monitoring (Administrator PowerShell)

```powershell
cd C:\SentinelIQ\sensor
$env:ML_SERVICE_API_KEY = (Get-Content ..\apps\backend\.env | Select-String '^ML_SERVICE_API_KEY=').ToString().Split('=')[1]

..\apps\ml-service\.venv\Scripts\python.exe -m netsensor live `
    --bundle C:\datasets\dos-models\dos-xgb-d0311-v1 `
    --interface "YOUR_INTERFACE_NAME" `
    --api http://127.0.0.1:4000/api `
    --organization-id YOUR_ORG_ID --endpoint-id YOUR_ENDPOINT_ID `
    --warmup-seconds 5
```

It prints a JSON status line every ~2 seconds: interface, packets, bytes, windows scored, alerts.
While it runs, the sensor endpoint shows **ONLINE** in the dashboard (it heartbeats the existing
endpoint API). Stop it with **Ctrl+C** — this stops the sniffer, flushes the final windows and
closes the capture handle cleanly.

Useful limits: `--max-seconds 120` (auto-stop), `--max-packets 500000`, `--allow-remote` (only if the
backend is deliberately non-local).

## Confirm real packets are being captured

The status line's `packets` and `bytes` counters rise as traffic flows. `windows_scored` increases
every 5 seconds of captured traffic. If `packets` stays 0, the interface is wrong or there is no
traffic on it (try the interface carrying your normal traffic, and generate some by browsing).

## See a live detection on the dashboard

The model keys on a **large number of distinct source ports** to one target across consecutive
5-second windows. Ordinary browsing will **not** trigger it (correctly). To see a genuine detection
you need real DoS-shaped traffic on the monitored interface. The honest ways:

- Monitor a lab/isolated network where an **authorized** load test is running.
- Or demonstrate the exact same detection without live capture using
  [`docs/DOS_DEMO.md`](DOS_DEMO.md) (synthetic capture, clearly labelled, not live).

When a detection fires, it appears under **Detections** within a couple of seconds, labelled
**LIVE TELEMETRY** and **ML DETECTION**, with its window evidence (packet rate, unique source ports,
SYN ratio), timestamp, severity and the **T1498** MITRE mapping.

## What is distinct about LIVE vs PCAP replay

| | Live monitoring | PCAP replay / demo |
|---|---|---|
| `dataOrigin` (API, DB) | `LIVE` | `PCAP_REPLAY` |
| Dashboard badge | LIVE TELEMETRY | RECORDED TRAFFIC |
| Evidence | window + traffic + prediction (no capture files) | adds `pcap-provenance` (file names + hashes) |

## Safety and limits

- No new privileged control is exposed to the browser. You start/stop the sensor yourself in
  PowerShell on the machine doing the capture. The dashboard only **reflects** status (endpoint
  ONLINE) and shows detections.
- Bounded capture buffer (`--queue`-sized, default 100k frames); overflow is dropped and counted as
  `dropped`, never unbounded memory. Flow and window state are bounded by expiry/close.
- A DoS alert never isolates an endpoint or triggers any response — it only records a detection.
- The monitor logs only packet **metadata/features**, never payloads or credentials.
- **Model limits:** this model leans heavily on distinct source-port counts; it detects classic
  high-source-port SYN floods well but would likely **miss** low-source reflection/amplification
  floods. It is validated on one testbed (CIC-DDoS2019), not on production networks. See
  [`sensor/docs/dos-model-d0311-v1.md`](../sensor/docs/dos-model-d0311-v1.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `WARNING: No libpcap provider available` on `--list-interfaces` | Npcap is **not installed**. Interfaces still list, but capture sees zero packets. Install Npcap (WinPcap-compatible mode), then confirm with `--smoke-test`. |
| `--smoke-test` exits with Npcap instructions | scapy is present but there is no capture provider; install Npcap and reopen PowerShell as Administrator. |
| `--smoke-test` shows `capturing: false` (0 packets) | Wrong interface, or no traffic on it. Re-check `--list-interfaces`; pick the adapter carrying your traffic and browse a page during the test. |
| "Access denied" / no packets as admin | Npcap not installed in WinPcap-compatible mode; reinstall Npcap with that box checked. |
| Endpoint not ONLINE | Confirm `--organization-id`/`--endpoint-id` match the endpoint you created, and `ML_SERVICE_API_KEY` matches `apps/backend/.env`. |
| No detection on normal traffic | Expected — benign traffic is not an attack. The model needs a genuine high-source-port flood. |
| `ingest HTTP 4xx/5xx` | Backend down or ids wrong; confirm `http://127.0.0.1:4000/api/health` responds. |

## Verified vs needs-your-machine

**Verified here (disposable backend + model, no Atlas):**
- The complete path **synthetic frames → live rolling windows → trained model → persistence →
  genuine `LIVE` alert → real backend ingestion → stored DoS detection** (dataOrigin LIVE, detector
  TRAINED, MITRE T1498). Proven with an in-memory capture source so no Npcap is needed.
- A flood raises **exactly one** LIVE alert; **benign traffic raises none** (negative test); forward
  failures don't crash monitoring; stop closes the capture handle; the window-row schema matches the
  model input. (`tests/test_live.py`.)
- **Capture fails fast without Npcap** instead of silently capturing zero packets: a verified test
  confirms `ScapyCaptureSource` and the smoke test raise clear Npcap instructions when no capture
  provider is present (the exact "listing works but capture doesn't" trap on this machine).
- The backend forwarder and heartbeat reuse (`tests/test_ingest.py`).
- Full sensor suite: **151 tests OK** (1 skipped: the no-scapy path, since scapy is installed),
  including the offline pipeline (unchanged behaviour after the shared-loop refactor).

**This machine's status:** scapy 2.8.0 is installed but **Npcap is not** (`conf.use_pcap=False`,
`conf.L2listen=None`, no `wpcap.dll`). So `--list-interfaces` works but capture does not — the smoke
test correctly refuses. Install Npcap to enable capture.

**Needs your Windows machine (cannot run here):** the actual scapy/Npcap capture from a real NIC —
i.e. real packets arriving on an interface. Everything downstream of the capture source is verified.

## Tests

```powershell
cd C:\SentinelIQ\sensor
..\apps\ml-service\.venv\Scripts\python.exe -m unittest tests.test_live      # live pipeline (needs the model bundle)
.\.venv\Scripts\python.exe -m unittest tests.test_ingest tests.test_pipeline # forwarder/heartbeat + shared packet loop
```
