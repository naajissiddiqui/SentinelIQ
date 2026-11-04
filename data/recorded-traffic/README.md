# Recorded-traffic detections

Real alert payloads produced **offline** from recorded CIC-DDoS2019 traffic (2018-11-03). They are
**PCAP replay**, not live traffic, and every payload says so (`dataOrigin: "PCAP_REPLAY"`).

| File | Produced by | Contents |
|---|---|---|
| `pcap-replay-trained-model-alerts.jsonl` | `python -m netsensor predict` with bundle `dos-xgb-99b94241-afefb015` on the continuous extraction of captures `SAT-03-11-2018_0136` to `_0145` (held-out test group g5) | 3 alert episodes: the UDP-flood tail at the victim, the SYN flood at the victim, and SYN reply traffic to the attacker's address |
| `pcap-replay-heuristic-alerts.jsonl` | `demo/offline_demo.py` (packets-per-second **heuristic**, not a trained model) on capture `SAT-03-11-2018_0` | 1 alert episode: the NetBIOS flood onset |

Each payload carries its capture file names and SHA-256 hashes in its `pcap-provenance` evidence.
Byte-identical copies of the originals:
`C:\datasets\dos-models\dos-xgb-d0311-v1-predict-g5-episodes\alerts.jsonl` and
`C:\datasets\dos-demo\run1d\alerts.jsonl`.

Send them into the running application with `npm run replay:recorded -- --email <you>` (see
[docs/PRESENTATION.md](../../docs/PRESENTATION.md)). The backend stores each alert episode once, so
replaying them never creates duplicates.
