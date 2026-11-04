"""
Forward DoS/DDoS alert payloads (alerts.jsonl from `predict` / `heuristic`) to a
SentinelIQ backend's ingest endpoint.

    python -m netsensor ingest-alerts --alerts OUT/alerts.jsonl --api http://127.0.0.1:4000/api \
        --organization-id ORG --endpoint-id ENDPOINT [--api-key-env ML_SERVICE_API_KEY] [--dry-run]

Standard library only. Guards:
  - only local backends (127.0.0.1 / localhost / ::1) unless --allow-remote is given:
    sending detections to a shared or production backend is a deliberate act;
  - the service API key is read from an environment variable, never from the
    command line, and is never written to the log;
  - every payload must be an attackType DOS_DDOS alert that states its dataOrigin and a
    detectorStatus of TRAINED or HEURISTIC; anything else (e.g. a synthetic test model)
    is refused before anything is sent;
  - organizationId / endpointId placeholders from offline scoring are replaced by the
    given ids; nothing else in the payload is changed.

Writes a log (default ingest-log.jsonl next to the alerts, or --log PATH): one line per alert
with the HTTP status and the created detection id or the server's error. An existing log is
never overwritten. The backend deduplicates alert episodes, so re-sending an episode it already
holds returns the stored detection (HTTP 200, counted as "already_recorded"), never a second one.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
ACCEPTED_STATUSES = {"TRAINED", "HEURISTIC"}


class IngestError(ValueError):
    """A payload, target or configuration that must not be sent."""


def check_target(api: str, allow_remote: bool) -> str:
    parsed = urlparse(api)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise IngestError(f"--api must be an http(s) URL, got {api!r}")
    if parsed.hostname not in LOCAL_HOSTS and not allow_remote:
        raise IngestError(f"refusing to send to non-local backend {parsed.hostname}; pass --allow-remote deliberately")
    return api.rstrip("/") + "/detections/ingest"


def validate_payload(p: Dict[str, object], line: int) -> None:
    if p.get("attackType") != "DOS_DDOS":
        raise IngestError(f"line {line}: attackType {p.get('attackType')!r} is not DOS_DDOS")
    if p.get("dataOrigin") not in ("PCAP_REPLAY", "LIVE"):
        raise IngestError(f"line {line}: dataOrigin must be PCAP_REPLAY or LIVE")
    if p.get("detectorStatus") not in ACCEPTED_STATUSES:
        raise IngestError(f"line {line}: detectorStatus {p.get('detectorStatus')!r} is not TRAINED or HEURISTIC")
    if not isinstance(p.get("riskScore"), (int, float)):
        raise IngestError(f"line {line}: riskScore missing")


def load_alerts(path: str) -> List[Dict[str, object]]:
    alerts = []
    with open(path, encoding="utf-8") as stream:
        for i, raw in enumerate(stream, start=1):
            if not raw.strip():
                continue
            p = json.loads(raw)
            validate_payload(p, i)
            alerts.append(p)
    return alerts


def _post(url: str, body: bytes, api_key: str, timeout: float) -> (int, Dict[str, object]):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "x-api-key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"message": e.reason}


def forward(alerts_path: str, api: str, organization_id: str, endpoint_id: str, api_key: Optional[str],
            dry_run: bool = False, allow_remote: bool = False, timeout: float = 15.0,
            post: Callable = _post, log_path: Optional[str] = None) -> Dict[str, object]:
    url = check_target(api, allow_remote)
    organization_id, endpoint_id = organization_id.strip(), endpoint_id.strip()
    alerts = load_alerts(alerts_path)
    if not dry_run and not api_key:
        raise IngestError("no API key: set the environment variable named by --api-key-env")
    log_path = os.path.abspath(log_path or os.path.join(os.path.dirname(os.path.abspath(alerts_path)), "ingest-log.jsonl"))
    results = []
    if not dry_run and os.path.exists(log_path):
        raise IngestError(f"{log_path} exists: these alerts were already forwarded (refusing to send duplicates)")
    for p in alerts:
        body = dict(p)
        body.pop("_fixture", None)
        body["organizationId"], body["endpointId"] = organization_id, endpoint_id
        entry = {"detectedAt": body.get("detectedAt"), "target": _target(body), "riskScore": body.get("riskScore")}
        if dry_run:
            entry["status"] = "dry-run"
        else:
            status, reply = post(url, json.dumps(body).encode("utf-8"), api_key, timeout)
            stored = status == 201 or (status == 200 and reply.get("duplicate") is True)
            entry["http_status"] = status
            entry["result"] = "created" if status == 201 else "already_recorded" if stored else "failed"
            entry["detection_id"] = (reply.get("detection") or {}).get("_id") if stored else None
            entry["error"] = None if stored else (reply.get("message") or reply.get("error"))
        results.append(entry)
    if not dry_run:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "x", encoding="utf-8", newline="\n") as stream:
            for r in results:
                stream.write(json.dumps(r, sort_keys=True) + "\n")
    count = lambda kind: sum(1 for r in results if r.get("result") == kind)
    return {"url": url, "alerts": len(alerts), "created": count("created"), "already_recorded": count("already_recorded"),
            "dry_run": dry_run, "failed": 0 if dry_run else count("failed"), "log": None if dry_run else log_path,
            "detection_ids": [r.get("detection_id") for r in results if r.get("detection_id")]}


def live_forwarder(api: str, organization_id: str, endpoint_id: str, api_key: Optional[str],
                   allow_remote: bool = False, timeout: float = 15.0, post: Callable = _post) -> Callable:
    """
    Returns send(payload) for the LIVE sensor: validates the payload against the same rules as the
    file forwarder, stamps the organization/endpoint ids, POSTs to the backend ingest endpoint, and
    returns the stored detection id. The backend deduplicates alert episodes, so a repeated episode
    returns the existing detection (HTTP 200) rather than a second one.
    """
    url = check_target(api, allow_remote)
    if not api_key:
        raise IngestError("no API key: set the environment variable named by --api-key-env")
    org, ep = organization_id.strip(), endpoint_id.strip()

    def send(payload: Dict[str, object]) -> Optional[str]:
        validate_payload(payload, 0)
        body = dict(payload)
        body["organizationId"], body["endpointId"] = org, ep
        status, reply = post(url, json.dumps(body).encode("utf-8"), api_key, timeout)
        if status not in (200, 201):
            raise IngestError(f"ingest HTTP {status}: {reply.get('message') or reply.get('error')}")
        return (reply.get("detection") or {}).get("_id")

    return send


def heartbeat_sender(api: str, endpoint_id: str, api_key: Optional[str],
                     allow_remote: bool = False, timeout: float = 10.0, post: Callable = _post) -> Callable:
    """
    Returns heartbeat() -> bool that posts to the existing /endpoints/:id/heartbeat endpoint so the
    sensor shows ONLINE in the dashboard while it is monitoring. This reuses the validated,
    service-key-authenticated endpoint; it exposes no new privileged control. Failures are swallowed
    (a missed heartbeat must never stop monitoring).
    """
    base = check_target(api, allow_remote).rsplit("/detections/ingest", 1)[0]
    url = f"{base}/endpoints/{endpoint_id.strip()}/heartbeat"

    def beat() -> bool:
        if not api_key:
            return False
        try:
            status, _ = post(url, b"{}", api_key, timeout)
            return status == 200
        except Exception:
            return False

    return beat


def _target(p: Dict[str, object]) -> Optional[str]:
    for e in p.get("evidence") or []:
        if isinstance(e, dict) and e.get("id") == "dos-window":
            return (e.get("fields") or {}).get("target")
    return None
