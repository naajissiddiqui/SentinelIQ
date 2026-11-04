# Model card: `dos-xgb-99b94241-afefb015` (DoS/DDoS window model)

Bundle: `C:\datasets\dos-models\dos-xgb-d0311-v1\`. It holds the model, preprocessing,
`bundle.json` (schema fingerprint, feature order, threshold, config, seed, provenance)
and `report.json`/`report.md` (the evaluation).

## What it is
- **Model:** XGBoost on 5-second, per-destination `dos-window-v1` windows (47 features).
  - Selected on validation: 1 tree, `max_depth` 3.
  - The learned model is a **single split: `unique_src_ports >= 511` → attack**.
- **Alerting:** threshold 0.475, chosen on validation for a 0.1% false-positive target.
  An alert needs 2 of the last 3 windows over the threshold, and is raised **once per
  episode** for each destination.
- **Labels:** official CIC-DDoS2019 flow labels turned into window rules
  (`sensor/labels/cicddos2019_0311_v1.json`), verified by `verify_cicddos2019.py`
  (criteria v2, 8 of 8 checks pass).

## Data and split (one capture day: CIC-DDoS2019, 2018-11-03)
| Split | Groups | Attack windows | Benign windows | Attack families |
|---|---|---|---|---|
| train | g1–g3 | 265 | 9,937 | NETBIOS, LDAP, MSSQL |
| validation | g4 | 92 | 2,091 | UDP |
| test | g5 | 91 | 35,312 | SYN (never seen in training) |

The split runs forward in time. Each group is one continuous extraction with 180 s of
warm-up excluded; split boundaries are more than 180 s apart. Ambiguous windows are
excluded, including all attacker and victim windows outside flood cores, PORTMAP and UDP_LAG.

## Results (held-out SYN test, evaluated once)
- **XGBoost:**
  - PR-AUC 1.0; recall 1.0 (95% CI 0.959–1.0); FPR 0.0 (0–0.00011);
  - 0 false alerts in 49 benign destination-hours; detection delay 10 s.
- **Packets-per-second baseline:** recall 1.0; FPR 0.00074; precision 0.78;
  0.10 false alerts per benign destination-hour.
- **Validation metrics are optimistic:** the hyperparameters, early stopping and threshold
  were all chosen on validation.

## Limitations: read before relying on it
1. **One capture day, one testbed.** Every attack window targets one victim
   (192.168.50.4) from one attacker (172.16.0.5). Nothing here shows behaviour on
   other networks.
2. **A source-port-count shortcut.** The model uses only `unique_src_ports`. The CIC
   attacker randomises source ports in every flood, so that one count separates the
   classes. Real reflection or amplification floods (DNS, LDAP, NTP, ...) usually come
   from a *fixed* source port and many source addresses, and would likely be **missed**.
   The model ignores packet rate and the baseline features entirely.
3. **No confirmed benign windows for the victim.** The official labels mark the
   attacker's low-rate background toward the victim as attack all day, so every
   victim window outside a flood is ambiguous and excluded. All benign examples
   come from other hosts. The false-alert rate on the protected server itself is
   **not measured**.
4. **Limited cross-family generalisation.** SYN was held out and detected perfectly,
   but that is one family. It does not show generalisation to other families, to
   low-rate attacks, or to application-layer DoS.
5. **Easy data.** Inbound packet rate alone also separates every split (test attack
   windows run at 18k packets/s or more, benign at most 2k), so perfect scores here say
   little about subtle attacks.
6. **Coarse scores.** A single split outputs only two scores (0.475 / 0.525). The
   score is not a calibrated probability.

## Risk score and confidence (alert payloads)
`netsensor/ml/alerts.py::risk_assessment` produces a documented **severity, not a
probability**:

```
riskScore = round(40 + 20*margin + 20*persistence + 20*volume)    # 40..100
margin      = (score - threshold) / (1 - threshold)    (heuristic: (pps/threshold - 1) / 9)
persistence = over-threshold windows among the last n
volume      = log10(pps / reference) / 2, where reference = the bundle's validation pps threshold (470.8)
```

- **Confidence** is "likely" only for a `TRAINED` model with all n windows over the
  threshold and high volume; otherwise "suspicious". It is never "confirmed".
- **In practice alerts are "suspicious":** an alert is raised at the first window that
  meets k of n, so with 2-of-3 it carries 2 hits.
- **Sample values:** this model's held-out alerts score risk 69–73 (backend severity HIGH).
- **Visibility:** the components and score semantics travel in the alert evidence and
  are shown in the dashboard.

## Next steps that would change this card
- Retrain without the port-count features (validation only; keep this test result as the
  single test reading).
- Add an independent day (`PCAP-01-12` / `CSV-01-12`) and benign traffic for the
  protected server.
