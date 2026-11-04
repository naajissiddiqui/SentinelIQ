#!/usr/bin/env python3
"""
generate_dos_behavior.py
========================
One command that produces a network DoS detection end to end, the safe way this
project already does it: build a synthetic flood CAPTURE FILE, extract it, score
it with the trained model, and POST the resulting alert to your LOCAL backend.

This is the DoS counterpart to agent/generate_ransomware_behavior.py. Like the
PCAP generator it wraps, it NEVER transmits anything on any network: the "flood"
exists only as packets written into a .pcap file on disk, addressed to loopback.
The sensor reads that file, exactly as it would read a real capture.

Safety (inherited from the steps it calls):
  - tools.generate_dos_pcap opens no sockets and sends no packets; it only writes
    a file, and refuses any address outside loopback / documentation ranges.
  - netsensor ingest-alerts refuses any non-local backend unless --allow-remote.

Usage (from the sensor/ directory):
  <python> -m tools.generate_dos_behavior \
      --organization-id <ORG_ID> --endpoint-id <NETWORK_SENSOR_ENDPOINT_ID>

  # build and score only, send nothing:
  <python> -m tools.generate_dos_behavior --no-ingest

The backend API key is read from the environment variable named by --api-key-env
(default ML_SERVICE_API_KEY), the same variable the plain ingest step uses.
"""
import argparse
import datetime as _dt
import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SENSOR_ROOT = os.path.dirname(HERE)
sys.path.insert(0, SENSOR_ROOT)

DEFAULT_BUNDLE = r"C:\datasets\dos-models\dos-xgb-d0311-v1"


def _run_module(module: str, argv: list) -> None:
    """Run `python -m module argv...` in-process, restoring sys.argv after."""
    saved = sys.argv
    sys.argv = [module] + argv
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except SystemExit as exc:  # argparse / CLIs call sys.exit; treat non-zero as failure
        if exc.code:
            raise RuntimeError(f"step '{module}' exited with code {exc.code}") from exc
    finally:
        sys.argv = saved


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate a DoS detection end to end (safe, local, file-based).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--organization-id", help="your organization id (required unless --no-ingest)")
    ap.add_argument("--endpoint-id", help="the registered Network Sensor endpoint id (required unless --no-ingest)")
    ap.add_argument("--api", default="http://127.0.0.1:4000/api", help="local backend API base (default: %(default)s)")
    ap.add_argument("--api-key-env", default="ML_SERVICE_API_KEY", help="env var holding the backend service key")
    ap.add_argument("--bundle", default=DEFAULT_BUNDLE, help="trained model bundle (default: %(default)s)")
    ap.add_argument("--out-dir", help="run directory (default: dos-demo/run-<timestamp>)")
    ap.add_argument("--flood-seconds", type=int, default=20, help="length of the flood segment (default: 20)")
    ap.add_argument("--flood-pps", type=int, default=6000, help="flood packets per second (default: 6000)")
    ap.add_argument("--target-ip", default="127.0.0.1", help="loopback/doc target (default: 127.0.0.1)")
    ap.add_argument("--target-port", type=int, default=80)
    ap.add_argument(
        "--capture-time", choices=["now", "synthetic"], default="now",
        help="'now' timestamps the capture ending ~now so the detection sorts to the top of the "
             "Detections list (which orders by detectedAt); 'synthetic' keeps the generator's fixed "
             "historical timestamp (default: now)",
    )
    ap.add_argument("--no-ingest", action="store_true", help="build and score only; send nothing")
    ap.add_argument("--dry-run", action="store_true", help="do the ingest as a dry run (validate, send nothing)")
    args = ap.parse_args(argv)

    if not args.no_ingest and not args.dry_run and not (args.organization_id and args.endpoint_id):
        ap.error("--organization-id and --endpoint-id are required to ingest (or pass --no-ingest / --dry-run)")

    out_dir = args.out_dir or os.path.join(
        SENSOR_ROOT, "dos-demo", "run-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    pcap = os.path.join(out_dir, "dos.pcap")
    extract_dir = os.path.join(out_dir, "extract")
    predict_dir = os.path.join(out_dir, "predict")
    alerts = os.path.join(predict_dir, "alerts.jsonl")

    print(f"[1/4] building synthetic flood capture -> {pcap}")
    gen_argv = [
        "--out", pcap,
        "--target-ip", args.target_ip, "--target-port", str(args.target_port),
        "--flood-seconds", str(args.flood_seconds), "--flood-pps", str(args.flood_pps),
    ]
    if args.capture_time == "now":
        # The Detections list sorts by detectedAt; a fresh timestamp keeps the alert at the top.
        gen_argv.append("--now")
    _run_module("tools.generate_dos_pcap", gen_argv)

    print(f"[2/4] extracting windows -> {extract_dir}")
    _run_module("netsensor", ["extract", pcap, "--out-dir", extract_dir])

    print(f"[3/4] scoring with model {os.path.basename(args.bundle)} -> {predict_dir}")
    _run_module("netsensor", [
        "predict", "--bundle", args.bundle, "--extraction", extract_dir, "--out-dir", predict_dir,
    ])

    if args.no_ingest:
        print(f"[4/4] skipped (--no-ingest). Alerts written to {alerts}")
        return 0

    if not os.environ.get(args.api_key_env):
        ap.error(f"environment variable {args.api_key_env} is not set; export the backend service key first")

    ingest_argv = [
        "ingest-alerts", "--alerts", alerts, "--api", args.api,
        "--organization-id", args.organization_id or "", "--endpoint-id", args.endpoint_id or "",
        "--api-key-env", args.api_key_env,
    ]
    if args.dry_run:
        ingest_argv.append("--dry-run")
    print(f"[4/4] {'dry-run ingest to' if args.dry_run else 'sending alert to'} {args.api}")
    _run_module("netsensor", ingest_argv)
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
