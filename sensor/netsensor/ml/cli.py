"""
ML commands (run with the ml-service venv, from the sensor directory):

    python -m netsensor train --dataset DATASET_DIR [--config CONFIG.json] --out-dir BUNDLE_DIR
    python -m netsensor predict --bundle BUNDLE_DIR --extraction EXTRACTION_DIR --out-dir OUT
    python -m netsensor heuristic --extraction EXTRACTION_DIR --out-dir OUT [--threshold-pps 5000 --k 3 --n 3]

predict/heuristic stream an extraction's windows.csv, score every window,
apply k-of-n persistence per destination, and write:
  scores.csv       key columns, score, over_threshold, alert (condition holds), raised (episode starts)
  alerts.jsonl     one backend ingest payload per alert EPISODE, at the window that raises it
                   (an 8-minute flood is one alert, not one per window; nothing is sent anywhere)
  run.json         detector, status, inputs and counts
Exit codes: 0 ok, 2 bad input, 3 training refused.
"""

import argparse
import csv
import json
import os
import sys

from ..schema import FEATURE_NAMES, KEY_COLUMNS


def _score_extraction(detector, extraction_dir, out_dir, organization_id, endpoint_id, data_origin):
    from .alerts import detection_payload
    from .model import AlertTracker

    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise FileExistsError(f"refusing to overwrite {out_dir}")
    with open(os.path.join(extraction_dir, "stats.json"), encoding="utf-8") as stream:
        stats = json.load(stream)
    captures = [{"file": os.path.basename(i["path"]), "bytes": i["bytes"], "sha256": i.get("sha256")}
                for i in stats["inputs"]]
    os.makedirs(out_dir, exist_ok=True)
    tracker = AlertTracker(detector.persistence)
    counts = {"windows": 0, "over_threshold": 0, "alert_windows": 0, "alerts": 0}
    # windows.csv is ordered by slot, so per-destination time order holds.
    with open(os.path.join(extraction_dir, "windows.csv"), newline="", encoding="utf-8") as src, \
         open(os.path.join(out_dir, "scores.csv"), "w", newline="", encoding="utf-8") as scores_out, \
         open(os.path.join(out_dir, "alerts.jsonl"), "w", encoding="utf-8", newline="\n") as alerts_out:
        reader = csv.DictReader(src)
        if reader.fieldnames != KEY_COLUMNS + FEATURE_NAMES:
            raise ValueError("windows.csv columns differ from the dos-window-v1 schema")
        writer = csv.writer(scores_out, lineterminator="\n")
        writer.writerow(KEY_COLUMNS + ["score", "threshold", "over_threshold", "alert", "raised"])
        for row in reader:
            result = detector.score_window(row)
            state = tracker.observe(row["dst_ip"], int(row["window_start_ns"]), result["over_threshold"])
            writer.writerow([row[k] for k in KEY_COLUMNS] + [repr(result["score"]), repr(result["threshold"]),
                                                              int(result["over_threshold"]), int(state["active"]),
                                                              int(state["raised"])])
            counts["windows"] += 1
            counts["over_threshold"] += int(result["over_threshold"])
            counts["alert_windows"] += int(state["active"])
            if state["raised"]:
                counts["alerts"] += 1
                payload = detection_payload(row, result, organization_id=organization_id, endpoint_id=endpoint_id,
                                            data_origin=data_origin, persistence=detector.persistence,
                                            captures=captures, persistence_hits=state["hits"])
                alerts_out.write(json.dumps(payload, sort_keys=True) + "\n")
    run = {"detector": type(detector).__name__, "status": detector.status, "model_version": detector.model_version,
           "threshold": detector.threshold, "persistence": detector.persistence, "data_origin": data_origin,
           "extraction": os.path.abspath(extraction_dir), "captures": captures, "counts": counts,
           "labels_read": False}
    with open(os.path.join(out_dir, "run.json"), "w", encoding="utf-8", newline="\n") as stream:
        json.dump(run, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return run


def _run_live(args) -> int:
    import os
    # These two paths only test capture (scapy); they must not import the model libs (numpy/xgboost),
    # so they work from any venv that has scapy.
    from ..live import list_interfaces, capture_smoke_test

    if args.list_interfaces:
        print("# Listing works without Npcap and does NOT prove capture works; run --smoke-test to verify.", file=sys.stderr)
        for i, name in enumerate(list_interfaces()):
            print(f"[{i}] {name}")
        return 0

    if args.smoke_test:
        if not args.interface:
            print("error: --interface is required for --smoke-test", file=sys.stderr)
            return 2
        result = capture_smoke_test(args.interface, seconds=args.seconds)
        print(json.dumps(result))
        if not result["capturing"]:
            print("no packets captured: wrong interface, no traffic on it, or Npcap not active.", file=sys.stderr)
            return 1
        return 0

    # Full monitoring needs the model (numpy/xgboost) and the forwarder.
    from ..live import LiveMonitor, MonitorLimits, ScapyCaptureSource
    from .model import DosDetector as _DosDetector
    from ..ingest import live_forwarder, heartbeat_sender, IngestError  # noqa: F401

    missing = [f for f in ("bundle", "interface", "api", "organization_id", "endpoint_id") if not getattr(args, f)]
    if missing:
        print(f"error: --{missing[0].replace('_', '-')} is required for live monitoring", file=sys.stderr)
        return 2
    try:
        detector = _DosDetector.load(args.bundle)
        forward = live_forwarder(args.api, args.organization_id, args.endpoint_id,
                                 os.environ.get(args.api_key_env), allow_remote=args.allow_remote)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    limits = MonitorLimits(max_seconds=args.max_seconds, max_packets=args.max_packets, warmup_seconds=args.warmup_seconds)

    # Keep the sensor endpoint ONLINE in the dashboard while monitoring (reuses the existing,
    # authenticated heartbeat endpoint; adds no new privileged control surface).
    beat = heartbeat_sender(args.api, args.endpoint_id, os.environ.get(args.api_key_env), allow_remote=args.allow_remote)

    def on_status(s):
        if s["running"]:
            beat()
        print(json.dumps({"status": "monitoring" if s["running"] else "stopped", "interface": s["interface"],
                          "packets": s["packets"], "bytes": s["bytes"], "windows_scored": s["windows_scored"],
                          "alerts": s["alerts"], "dropped": s["dropped_packets"], "uptime_s": s["uptime_seconds"]}),
              flush=True)

    monitor = LiveMonitor(detector, args.organization_id, args.endpoint_id, forward, limits=limits, on_status=on_status)
    source = ScapyCaptureSource(args.interface, linktype=args.linktype, queue_size=limits.queue_size)
    print(f"[live] monitoring interface {args.interface} with bundle {detector.model_version}; Ctrl+C to stop", flush=True)
    import signal
    signal.signal(signal.SIGINT, lambda *_: monitor.stop())
    status = monitor.run(source)
    print(json.dumps({"final": status.as_dict()}, default=str))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="netsensor")
    sub = parser.add_subparsers(dest="command", required=True)
    tr = sub.add_parser("train", help="train the XGBoost window model on a built dataset")
    tr.add_argument("--dataset", required=True)
    tr.add_argument("--config", help="JSON overrides of train.DEFAULT_CONFIG")
    tr.add_argument("--out-dir", required=True)
    for name, help_text in (("predict", "score an extraction with a trained bundle"),
                            ("heuristic", "score an extraction with the pps heuristic (not a model)")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--extraction", required=True, help="directory with windows.csv and stats.json")
        p.add_argument("--out-dir", required=True)
        p.add_argument("--organization-id", default="000000000000000000000000")
        p.add_argument("--endpoint-id", default="000000000000000000000000")
        p.add_argument("--data-origin", default="PCAP_REPLAY", choices=["PCAP_REPLAY", "LIVE"])
        if name == "predict":
            p.add_argument("--bundle", required=True)
        else:
            p.add_argument("--threshold-pps", type=float, default=5000.0)
            p.add_argument("--k", type=int, default=3)
            p.add_argument("--n", type=int, default=3)

    lv = sub.add_parser("live", help="continuously monitor a live interface with a trained bundle")
    lv.add_argument("--bundle", help="trained model bundle directory")
    lv.add_argument("--interface", help="network interface to capture from (see --list-interfaces)")
    lv.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    lv.add_argument("--smoke-test", action="store_true", help="count packets on --interface for --seconds, then exit (no model, no alerts)")
    lv.add_argument("--seconds", type=float, default=5.0, help="duration for --smoke-test")
    lv.add_argument("--api", help="backend API base URL, e.g. http://127.0.0.1:4000/api")
    lv.add_argument("--organization-id")
    lv.add_argument("--endpoint-id")
    lv.add_argument("--api-key-env", default="ML_SERVICE_API_KEY")
    lv.add_argument("--allow-remote", action="store_true", help="allow a non-local backend (deliberate)")
    lv.add_argument("--max-seconds", type=float, default=0.0, help="stop after N seconds (0 = until Ctrl+C)")
    lv.add_argument("--max-packets", type=int, default=0, help="stop after N packets (0 = unbounded)")
    lv.add_argument("--warmup-seconds", type=float, default=5.0)
    lv.add_argument("--linktype", type=int, default=1, help="libpcap link type of the interface (1 = Ethernet)")
    args = parser.parse_args(argv)

    if args.command == "live":
        return _run_live(args)

    from .features import FeatureError
    from .model import BundleError, DosDetector, PpsHeuristic
    from .train import TrainingRefused, train

    try:
        if args.command == "train":
            config = None
            if args.config:
                with open(args.config, encoding="utf-8") as stream:
                    config = json.load(stream)
            bundle = train(args.dataset, args.out_dir, config)
            print(json.dumps({k: bundle[k] for k in ("model_version", "status", "threshold")}))
            return 0
        detector = DosDetector.load(args.bundle) if args.command == "predict" else \
            PpsHeuristic(args.threshold_pps, args.k, args.n)
        run = _score_extraction(detector, args.extraction, args.out_dir, args.organization_id,
                                args.endpoint_id, args.data_origin)
        print(json.dumps({"status": run["status"], **run["counts"]}))
        return 0
    except TrainingRefused as refused:
        print("training refused:", file=sys.stderr)
        for reason in refused.reasons:
            print(f"  - {reason}", file=sys.stderr)
        return 3
    except (FeatureError, BundleError, FileExistsError, FileNotFoundError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
