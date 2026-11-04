"""
Command line: extract flows and 5-second windows from recorded PCAP files, and
build a split, labelled window dataset from finished extractions.

    python -m netsensor extract --out-dir OUT capture1.pcap [capture2.pcap ...]
    python -m netsensor build-dataset --plan PLAN.json [--labels RULES.json] --out-dir OUT
    python -m netsensor run-jobs --jobs JOBS.json [--dry-run] [--only ID ...]
    python -m netsensor ingest-alerts --alerts alerts.jsonl --api URL --organization-id ID --endpoint-id ID

Training, evaluation and scoring need numpy/xgboost (the ml-service venv):
    python -m netsensor train | predict | heuristic ...   (see netsensor/ml/cli.py)

Offline only. Reads files; never captures from or transmits on a network.
"""

import argparse
import json
import sys

from .dataset import DatasetError, build_dataset
from .labels import LabelRuleError, load_rules
from .pcap_reader import PcapFormatError
from .pipeline import extract_to_dir
from .ingest import IngestError, forward
from .runner import JobError, run_jobs

ML_COMMANDS = ("train", "predict", "heuristic", "live")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in ML_COMMANDS:
        # `live --list-interfaces` and `live --smoke-test` only check the capture path (scapy); they
        # never load the model, so they do not need numpy/xgboost.
        light_live = argv[0] == "live" and any(a in argv for a in ("--list-interfaces", "--smoke-test"))
        if not light_live:
            # Imported only here: the extractor itself stays standard-library only.
            import importlib.util
            missing = [m for m in ("numpy", "sklearn", "xgboost") if importlib.util.find_spec(m) is None]
            if missing:
                print(f"error: '{argv[0]}' needs numpy, scikit-learn and xgboost (missing: {', '.join(missing)}). "
                      r"Run it with the ml-service venv: ..\apps\ml-service\.venv\Scripts\python.exe -m netsensor "
                      + argv[0], file=sys.stderr)
                return 2
        from .ml.cli import main as ml_main
        return ml_main(argv)
    parser = argparse.ArgumentParser(prog="netsensor")
    sub = parser.add_subparsers(dest="command", required=True)
    ext = sub.add_parser("extract", help="PCAP/pcapng files -> windows.csv, flows.csv, stats.json")
    ext.add_argument("pcaps", nargs="+", help="capture files, processed in the order given")
    ext.add_argument("--out-dir", required=True)
    ext.add_argument("--no-flows", action="store_true", help="skip flows.csv")
    ext.add_argument("--no-hash", action="store_true", help="skip SHA-256 of the inputs")
    ext.add_argument("--force", action="store_true", help="overwrite existing outputs")
    ds = sub.add_parser("build-dataset", help="extraction outputs -> features/labels/splits CSVs + manifest")
    ds.add_argument("--plan", required=True, help="JSON plan: sources and their split assignment")
    ds.add_argument("--labels", help="JSON label rules; without it every row is 'unlabelled'")
    ds.add_argument(
        "--allow-unverified-labels",
        action="store_true",
        help="accept rules whose provenance is not verified (the dataset is then marked untrusted)",
    )
    ds.add_argument("--out-dir", required=True)
    jobs = sub.add_parser("run-jobs", help="bounded continuous extractions with resource guards and resume")
    jobs.add_argument("--jobs", required=True, help="JSON job file (see netsensor/runner.py)")
    jobs.add_argument("--dry-run", action="store_true", help="show plan, estimates and preflight; write nothing")
    jobs.add_argument("--only", nargs="+", help="run only these job ids")
    ing = sub.add_parser("ingest-alerts", help="POST alert payloads to a (local) SentinelIQ backend")
    ing.add_argument("--alerts", required=True, help="alerts.jsonl from predict/heuristic")
    ing.add_argument("--api", required=True, help="backend API base URL, e.g. http://127.0.0.1:4000/api")
    ing.add_argument("--organization-id", required=True)
    ing.add_argument("--endpoint-id", required=True, help="the registered network-sensor endpoint")
    ing.add_argument("--api-key-env", default="ML_SERVICE_API_KEY", help="environment variable holding the service API key")
    ing.add_argument("--dry-run", action="store_true")
    ing.add_argument("--log", help="where to write the ingest log (default: ingest-log.jsonl next to the alerts); never overwritten")
    ing.add_argument("--allow-remote", action="store_true", help="allow a non-local backend (deliberate)")
    args = parser.parse_args(argv)

    if args.command == "ingest-alerts":
        import os
        try:
            result = forward(args.alerts, args.api, args.organization_id, args.endpoint_id,
                             os.environ.get(args.api_key_env), dry_run=args.dry_run, allow_remote=args.allow_remote,
                             log_path=args.log)
        except (IngestError, FileNotFoundError, ValueError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        except OSError as error:
            print(f"error: backend unreachable: {error}", file=sys.stderr)
            return 2
        print(json.dumps(result))
        return 0 if result["failed"] == 0 else 3

    if args.command == "run-jobs":
        try:
            results = run_jobs(args.jobs, dry_run=args.dry_run, only=args.only)
        except (JobError, FileNotFoundError, json.JSONDecodeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(results))
        return 0 if all(r["status"] in ("complete", "skipped-verified", "dry-run") for r in results) else 3

    if args.command == "build-dataset":
        try:
            rules = load_rules(args.labels, args.allow_unverified_labels) if args.labels else None
            manifest = build_dataset(args.plan, args.out_dir, rules)
        except (DatasetError, LabelRuleError, FileExistsError, FileNotFoundError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps({k: manifest[k] for k in ("rows_total", "usable_for_training")}))
        return 0

    try:
        summary = extract_to_dir(
            args.pcaps,
            args.out_dir,
            write_flows=not args.no_flows,
            hash_inputs=not args.no_hash,
            force=args.force,
        )
    except (PcapFormatError, FileExistsError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({k: summary[k] for k in ("windows_written", "flows_written")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
