# Presenting SentinelIQ (real application)

This guide runs the real backend (your `apps/backend/.env`, i.e. the Atlas database and the Polygon
Amoy configuration) and the real web app. The network detection comes from **recorded traffic**: CIC-DDoS2019 captures,
scored offline by the network sensor's machine-learning detector and sent through the real
ingestion API. Nothing in it is live monitoring, and the app says so on every screen.

## 1. Start the application (two terminals)

```powershell
cd C:\SentinelIQ
npm run dev:backend      # API on http://localhost:4000 (wait for "Listening on http://localhost:4000")
```

```powershell
cd C:\SentinelIQ
npm run dev:web          # web app on http://localhost:3000 (wait for "Ready")
```

Open http://localhost:3000 and sign in with your own account.

## 2. Send the recorded network detections (third terminal)

```powershell
cd C:\SentinelIQ
npm run replay:recorded -- --email <your sign-in email>
```

The command asks for your password, which is never printed. Then it:

1. Signs in through `POST /auth/login`.
2. Finds or registers the endpoint **"Network Sensor (recorded traffic)"** through
   `POST /endpoints`. This step needs an organisation admin account.
3. Runs the sensor's own forwarder (`python -m netsensor ingest-alerts`) on
   `data/recorded-traffic/pcap-replay-trained-model-alerts.jsonl`. That file holds three alert
   episodes from the trained model's run on held-out test captures. They are sent to
   `POST /detections/ingest` with the backend's service key.

It prints one link per detection. The first run reports `newly recorded: 3`. Every later run
reports `already recorded (deduplicated): 3` with the same links: the backend stores each alert
episode once. You can rehearse as often as you like without creating duplicates. To send the
packet-rate rule's alert as well, add
`--alerts data/recorded-traffic/pcap-replay-heuristic-alerts.jsonl`.

## 3. Walkthrough (about 8 minutes)

| Step | Show | Say |
|---|---|---|
| 1 | Terminal output of `replay:recorded` | "These detections come from recorded attack traffic, scored by our machine-learning network detector. They go through the real API, and replays are deduplicated." |
| 2 | **Dashboard** | "Active detections, severity mix and MITRE ATT&CK coverage are all computed by the backend. Detection Sources separates recorded traffic from live telemetry." |
| 3 | **Detections** | "Each row shows threat type, data source and detector. The dates are the original 2018 capture times." |
| 4 | Open a detection | "Window evidence: packet rate, unique sources, persistence. Capture provenance lists the exact capture files and their hashes. ATT&CK T1498, with the reason it applies. Network DoS alerts are informational, so no endpoint is isolated." |
| 5 | Open **Model information** | "Model version, score meaning and how the 0–100 risk score is derived. It is a severity, not a probability." |
| 6 | **CTI Feed** → *Demonstration records* | "Threat-intelligence reports are anchored on Polygon Amoy. These two were made from demonstration data to exercise the workflow, and are labelled that way. The second corrects the first, which stays on-chain unchanged." |
| 7 | **Verify Report** → click a report ID | "Verification recomputes the report hash and compares it with the value stored on-chain." |

## What not to claim

- That the traffic is live: it is recorded and analysed after the fact.
- That live Windows endpoint monitoring was shown. Sysmon is not installed on the development
  machine, so it was not verified.
- That the risk score is a probability, or that the network detector generalises beyond the
  CIC-DDoS2019 testbed. See [`sensor/docs/dos-model-d0311-v1.md`](../sensor/docs/dos-model-d0311-v1.md).
- That the demonstration CTI reports are threat intelligence.

## Optional: an isolated rehearsal environment

`npm run demo` (with `MONGOD_BIN` set to a local `mongod`) starts a separate copy of the stack
against a temporary database and loads the same recorded traffic. Use it to rehearse without
touching your real data. It is not the application you present. See [DEMO.md](DEMO.md).
