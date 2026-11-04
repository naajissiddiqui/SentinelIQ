"""
Derive window label rules for one CIC-DDoS2019 day from the OFFICIAL flow CSVs.

    python -I derive_cicddos2019.py --csv-dir C:/CSV-03-11/03-11 --archive C:/.../CSV-03-11.zip \
        --csv-utc-offset -03:00 --out cicddos2019_0311_v1.json

Standard library only; streams the CSVs (several GB) at below-normal priority.

How the official labels work (measured on 03-11): a flow is labelled with an
attack name if and only if it is between the attacker and the victim (two
directed address pairs); the name follows the CSV file's time slice, so a
flood's first minute can carry the previous file's name, and the attacker's
continuous low-rate background toward the victim is labelled attack all day.

Derivation (every parameter is recorded in the output):
  1. Count, per second, attack-labelled flows whose destination is the victim.
  2. A flood second has at least --flood-flows-per-s flows. Flood seconds
     closer than --merge-gap-s are merged into one episode; episodes shorter
     than --min-episode-s are dropped (isolated spikes).
  3. Each episode becomes an attack interval [first second, last second + 1 s)
     for the victim. Its family is the majority official label inside it; the
     full label composition is recorded so artefacts stay visible.
  4. One exclude interval covers the victim and the attacker for the whole
     local calendar day(s) of the CSVs: their windows outside flood cores
     (background, decaying tails, low-rate attacks the flow labels cannot
     separate from it) become ambiguous, never benign.
  5. Every other destination is benign by rule: the official CSVs contain no
     attack-labelled flow to any other address (checked here; the script fails
     if that is not so).

The CSV clock offset is NOT guessed: it must be given, and must have been
measured beforehand by matching official flows to PCAP-derived flows. The
output is written with verified=false; a person sets verified, verified_by
and verified_on after reviewing it.
"""

import argparse
import ctypes
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

FAMILY = {"Portmap": "PORTMAP", "NetBIOS": "NETBIOS", "LDAP": "LDAP", "MSSQL": "MSSQL",
          "UDP": "UDP", "UDPLag": "UDP_LAG", "Syn": "SYN"}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 22), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-dir", required=True)
    ap.add_argument("--archive", required=True, help="the official ZIP the CSVs came from (hashed)")
    ap.add_argument("--csv-utc-offset", required=True, help="measured clock offset of the CSV timestamps, e.g. -03:00")
    ap.add_argument("--victim", default="192.168.50.4")
    ap.add_argument("--attacker", default="172.16.0.5")
    ap.add_argument("--flood-flows-per-s", type=int, default=100)
    ap.add_argument("--merge-gap-s", type=int, default=10)
    ap.add_argument("--min-episode-s", type=int, default=20)
    ap.add_argument("--guard-s", type=int, default=10)
    ap.add_argument("--version", default="cicddos2019-0311-v1")
    ap.add_argument("--timezone-evidence", default="", help="summary of the offset measurement")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if os.path.exists(args.out):
        sys.exit(f"refusing to overwrite {args.out}")
    if os.name == "nt":
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x4000)
    tz = timezone(datetime.strptime(args.csv_utc_offset.replace(":", ""), "%z").utcoffset())

    per_second = defaultdict(Counter)
    other_attack_dsts = Counter()
    first_ts = last_ts = None
    files = []
    for name in sorted(os.listdir(args.csv_dir)):
        if not name.endswith(".csv"):
            continue
        path = os.path.join(args.csv_dir, name)
        files.append({"name": name, "bytes": os.path.getsize(path), "sha256": sha256_file(path)})
        with open(path, encoding="utf-8", errors="replace") as f:
            header = [c.strip() for c in next(f).split(",")]
            i_src, i_dst, i_ts, i_lab = (header.index(c) for c in ("Source IP", "Destination IP", "Timestamp", "Label"))
            for line in f:
                p = line.rstrip("\r\n").split(",")
                src, dst, ts, label = p[i_src], p[i_dst], p[i_ts], p[i_lab].strip()
                first_ts = ts if first_ts is None or ts < first_ts else first_ts
                last_ts = ts if last_ts is None or ts > last_ts else last_ts
                if label == "BENIGN":
                    continue
                if {src, dst} != {args.victim, args.attacker}:
                    other_attack_dsts[(src, dst)] += 1
                elif dst == args.victim:
                    per_second[ts[:19]][label] += 1
        print(name, "read", flush=True)
    if other_attack_dsts:
        sys.exit(f"attack-labelled flows outside the attacker/victim pair: {other_attack_dsts.most_common(5)}")

    def local(s):
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)

    episodes = []
    for second in sorted(per_second):
        if sum(per_second[second].values()) < args.flood_flows_per_s:
            continue
        t = local(second)
        if episodes and (t - episodes[-1]["last"]).total_seconds() <= args.merge_gap_s:
            episodes[-1]["last"] = t
        else:
            episodes.append({"first": t, "last": t, "labels": Counter()})
        episodes[-1]["labels"].update(per_second[second])
    intervals = []
    dropped = []
    for ep in episodes:
        length = (ep["last"] - ep["first"]).total_seconds() + 1
        record = {"start": ep["first"].isoformat(), "end": (ep["last"] + timedelta(seconds=1)).isoformat(),
                  "official_label_counts": dict(ep["labels"].most_common())}
        if length < args.min_episode_s:
            dropped.append(record)
            continue
        label, count = ep["labels"].most_common(1)[0]
        family = FAMILY.get(label, label.upper())
        n = sum(1 for iv in intervals if iv["family"] == family) + 1
        intervals.append(dict(record, id=f"{family.lower()}-{n}", family=family, victims=[args.victim],
                              majority_share=round(count / sum(ep["labels"].values()), 4)))
    # Whole local calendar days: windows of these two addresses are never
    # benign, including seconds the CSVs do not cover (the PCAP runs slightly longer).
    span_start = local(first_ts[:10] + " 00:00:00")
    span_end = local(last_ts[:10] + " 00:00:00") + timedelta(days=1)
    intervals.append({"id": "attacker-victim-background", "kind": "exclude",
                      "start": span_start.isoformat(), "end": span_end.isoformat(),
                      "victims": [args.victim, args.attacker]})

    archive = os.path.abspath(args.archive)
    doc = {
        "label_rules_version": args.version,
        "dataset": "CIC-DDoS2019",
        "provenance": {
            "source": "Canadian Institute for Cybersecurity (UNB), CIC-DDoS2019 official CICFlowMeter CSVs",
            "dataset_page": "https://www.unb.ca/cic/datasets/ddos-2019.html",
            "download": "http://cicresearch.ca/CICDataset/CICDDoS2019/ (registration form)",
            "citation": "I. Sharafaldin, A. H. Lashkari, S. Hakak, A. A. Ghorbani, 'Developing Realistic "
                        "Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy', IEEE ICCST 2019",
            "archive": {"name": os.path.basename(archive), "bytes": os.path.getsize(archive),
                        "sha256": sha256_file(archive)},
            "source_files": files,
            "csv_clock_utc_offset": args.csv_utc_offset,
            "timezone_evidence": args.timezone_evidence,
            "derivation": {"script": "sensor/labels/derive_cicddos2019.py",
                           "victim": args.victim, "attacker": args.attacker,
                           "flood_flows_per_s": args.flood_flows_per_s, "merge_gap_s": args.merge_gap_s,
                           "min_episode_s": args.min_episode_s,
                           "csv_first_timestamp": first_ts, "csv_last_timestamp": last_ts,
                           "dropped_short_episodes": dropped},
            "verified": False,
            "verified_by": "",
            "verified_on": "",
            "notes": "Derived automatically; pending human review. Low-rate families (PORTMAP, UDP_LAG) and "
                     "the attacker's background are ambiguous, not attack: flow labels cannot separate them.",
        },
        "guard_seconds": args.guard_s,
        "intervals": intervals,
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(doc, stream, indent=2)
        stream.write("\n")
    print(json.dumps([{k: iv[k] for k in ("id", "start", "end")} for iv in intervals], indent=1))


if __name__ == "__main__":
    main()
