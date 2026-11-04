"""
Build the backend ingest payload (`POST /api/detections/ingest`) for a DoS/DDoS alert.

Nothing here sends anything: callers write the payload to a file or hand it
to a local test. The payload states plainly what produced it:

  - attackType "DOS_DDOS"; ruleId "DOS-XGB" (trained model) or
    "DOS-PPS-HEURISTIC" (heuristic);
  - detectorStatus TRAINED / SYNTHETIC_TEST_ONLY / HEURISTIC;
  - dataOrigin PCAP_REPLAY or LIVE. Offline capture processing is always
    PCAP_REPLAY; it is never presented as live traffic;
  - riskScore is a documented SEVERITY, not a probability (see risk_assessment);
    its components are in the evidence;
  - confidenceTier is "likely" only for a TRAINED model whose alert is fully
    persistent (n of n windows) at high volume; otherwise "suspicious". Never
    "confirmed": a model alone does not confirm an attack.
  - MITRE is left to the backend (T1498 for DOS_DDOS); no sub-technique is
    inferred, and dataset labels are never included.
"""

import math
from typing import Dict, List, Mapping, Optional

from . import STATUS_HEURISTIC, STATUS_TRAINED

DATA_ORIGINS = ("PCAP_REPLAY", "LIVE")
PROTOCOL_SHARES = ("in_tcp_share", "in_udp_share", "in_icmp_share", "in_other_share")

SCORE_SEMANTICS = {
    "xgboost": "uncalibrated XGBoost output; only its order relative to the threshold is meaningful, "
               "it is not a probability of attack",
    "pps-heuristic": "inbound packets per second (the heuristic's own measurement)",
}


def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def risk_assessment(result: Mapping[str, object], pps: float, hits: Optional[int] = None,
                    n: Optional[int] = None, k: Optional[int] = None) -> Dict[str, object]:
    """
    Severity for an alert, 40-100, from three evidence components in [0, 1]:

      margin       how far the score sits above the threshold. Model:
                   (score - t) / (1 - t). Heuristic: (pps / t - 1) / 9, so 10x
                   the threshold is 1;
      persistence  over-threshold windows among the last n (an alert has >= k);
      volume       log10(pps / reference) / 2, so 100x the reference pps is 1.
                   The reference is the bundle's validation-chosen pps threshold
                   (the heuristic uses its own threshold).

      riskScore = round(40 + 20 * margin + 20 * persistence + 20 * volume)

    No component is a probability, and the result is not calibrated: it ranks
    alerts by how strong and sustained the evidence is. A model with coarse
    scores (e.g. a single split) contributes almost nothing through "margin",
    which is the honest outcome.
    """
    score, t = float(result["score"]), float(result["threshold"])
    if result["status"] == STATUS_HEURISTIC:
        margin = _clamp((score / t - 1) / 9) if t > 0 else 0.0
    else:
        margin = _clamp((score - t) / (1 - t)) if t < 1 else 0.0
    if n is None or hits is None:
        n = n or 1
        hits = k if k is not None else n
    persistence = _clamp(hits / n)
    ref = float(result.get("volume_reference_pps") or 0)
    volume = _clamp(math.log10(pps / ref) / 2) if ref > 0 and pps > 0 else 0.0
    risk = int(round(40 + 20 * margin + 20 * persistence + 20 * volume))
    likely = result["status"] == STATUS_TRAINED and hits >= n and volume >= 0.5
    return {
        "riskScore": risk,
        "confidenceTier": "likely" if likely else "suspicious",
        "components": {"margin": round(margin, 4), "persistence": round(persistence, 4), "volume": round(volume, 4)},
        "persistenceHits": hits, "persistenceWindows": n,
        "volumeReferencePps": ref or None,
        "formula": "round(40 + 20*margin + 20*persistence + 20*volume); not a probability, not calibrated",
    }


def risk_score(result: Mapping[str, object], pps: Optional[float] = None) -> int:
    """Back-compatible helper: severity with full persistence assumed."""
    return int(risk_assessment(result, float(result["score"]) if pps is None else pps)["riskScore"])


def detection_payload(
    window: Mapping[str, object],
    result: Mapping[str, object],
    *,
    organization_id: str,
    endpoint_id: str,
    data_origin: str,
    persistence: Mapping[str, int],
    captures: Optional[List[Dict[str, object]]] = None,
    persistence_hits: Optional[int] = None,
) -> Dict[str, object]:
    if data_origin not in DATA_ORIGINS:
        raise ValueError(f"data_origin must be one of {DATA_ORIGINS}")
    pps = float(window["in_pkts_per_s"])
    assessment = risk_assessment(result, pps, persistence_hits, int(persistence["n"]), int(persistence["k"]))
    window_start_ns = int(window["window_start_ns"])
    when = window["window_start_utc"]
    baseline = window["in_pps_ratio_baseline"]
    # Evidence items follow the backend's EvidenceItem shape: id, source, time, description, fields.
    evidence = [
        {"id": "dos-window", "source": "netsensor", "time": when,
         "description": f"5 s window for {window['dst_ip']} starting {when}",
         "fields": {"target": window["dst_ip"], "windowStartNs": str(window_start_ns), "windowSeconds": 5}},
        {"id": "dos-prediction", "source": "netsensor", "time": when,
         "description": f"{result['detector']} score {result['score']:.4g} >= threshold {result['threshold']:.4g}",
         "fields": {"score": result["score"], "threshold": result["threshold"], "detector": result["detector"],
                    "detectorStatus": result["status"], "modelVersion": result["model_version"],
                    "schemaVersion": result["schema_version"], "persistence": dict(persistence),
                    "persistenceHits": assessment["persistenceHits"],
                    "scoreSemantics": SCORE_SEMANTICS.get(str(result["detector"]), "detector-specific score"),
                    "riskScoreDerivation": assessment["formula"],
                    "riskComponents": assessment["components"],
                    "volumeReferencePps": assessment["volumeReferencePps"]}},
        {"id": "dos-traffic", "source": "netsensor", "time": when,
         "description": "Inbound traffic summary for the window",
         "fields": {"inPacketsPerSecond": float(window["in_pkts_per_s"]),
                    "inBytesPerSecond": float(window["in_bytes_per_s"]),
                    "uniqueSources": float(window["unique_src"]), "newFlows": float(window["flows_new"]),
                    "unansweredFlowShare": float(window["unanswered_flow_share"]),
                    "baselinePpsRatio": None if str(baseline) == "nan" else float(baseline),
                    "protocolMix": {k: float(window[k]) for k in PROTOCOL_SHARES},
                    "topFeatures": result["top_features"],
                    "outOfTrainingRange": result["out_of_training_range"]}},
    ]
    if captures:
        evidence.append({"id": "pcap-provenance", "source": "netsensor", "time": when,
                         "description": f"{len(captures)} capture file(s), processed offline",
                         "fields": {"captures": captures}})
    return {
        "organizationId": organization_id,
        "endpointId": endpoint_id,
        "attackType": "DOS_DDOS",
        "ruleId": result["rule_id"],
        "riskScore": assessment["riskScore"],
        "confidenceTier": assessment["confidenceTier"],
        "modelVersion": result["model_version"],
        "detectorStatus": result["status"],
        "dataOrigin": data_origin,
        "detectedAt": window["window_start_utc"],
        "indicators": [
            # observedAt is the window's own time: for PCAP replay that is the capture time,
            # not the moment the alert was forwarded.
            {"type": "NETWORK_FLOOD", "observedAt": when,
             "description": f"{float(window['in_pkts_per_s']):.0f} packets/s inbound to "
                            f"{window['dst_ip']} ({result['detector']}, {result['status']})"},
        ],
        "evidence": evidence,
    }
