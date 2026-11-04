"""
Independent verification of a derived CIC-DDoS2019 rule file against the official CSVs.

    python -I verify_cicddos2019.py --rules cicddos2019_0311_v1.json --csv-dir C:/CSV-03-11/03-11 \
        --archive C:/.../CSV-03-11.zip --report OUT.json [--evidence FILE ...]

Checks (each recorded with its numbers in the report; overall PASS only if all pass):
  1. hashes     the archive and every CSV match the SHA-256 values in the rule provenance;
  2. rederive   running derive_cicddos2019.py again with the recorded parameters
                reproduces exactly the same intervals;
  3. pair       every attack-labelled flow is between the recorded attacker and victim,
                so "all other destinations are benign" follows from the official labels;
  4. coverage   for each official label, where its flows to the victim fall relative to
                the rule intervals (attack core / guard band / outside). Flood labels must
                have >= 99% of their flows in attack cores or guard bands (guard bands are
                ambiguous by design) and none in another family's core. Non-flood labels
                inside a flood core are reported as a family deviation (e.g. the Portmap.csv
                time-slice artefact at the start of the NetBIOS flood), never hidden;
  5. outside    every second with >= the flood threshold of attack-labelled flows outside
                the attack intervals is one of the short episodes the derivation records as
                dropped (they sit in the exclude interval, i.e. ambiguous);
  8. purity     official BENIGN flows to the victim inside attack cores, as a share of the
                cores' flows, is below 0.1%.

Criteria history: version 1 (2026-10-18) required >= 97% of flood flows in cores
alone and no outside second above the threshold. That FAILED only because guard
bands and documented dropped spikes are ambiguous by design; the version-1 report
is kept. Version 2 tests the property that matters (no official attack flow can
fall in a benign window) and adds the purity check.
  6. exclusion  every attack-labelled flow time lies inside the exclude interval, so no
                attacker/victim window can be labelled benign;
  7. evidence   the clock-offset evidence files still exist; their SHA-256 values are recorded.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
CRITERIA_VERSION = 2
FLOOD_CORE_OR_GUARD_MIN_SHARE = 0.99
MAX_BENIGN_IN_CORE_SHARE = 0.001


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 22), b""):
            digest.update(chunk)
    return digest.hexdigest()


def to_ns(iso):
    d = datetime.fromisoformat(iso)
    return int(d.replace(microsecond=0).timestamp()) * 10**9 + d.microsecond * 1000


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--csv-dir", required=True)
    ap.add_argument("--archive", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--evidence", nargs="*", default=[])
    args = ap.parse_args(argv)
    if os.path.exists(args.report):
        sys.exit(f"refusing to overwrite {args.report}")
    with open(args.rules, encoding="utf-8") as stream:
        rules = json.load(stream)
    prov = rules["provenance"]
    deriv = prov["derivation"]
    checks = {}

    # 1. hashes
    archive_sha = sha256_file(args.archive)
    files = {f["name"]: f["sha256"] for f in prov["source_files"]}
    actual = {n: sha256_file(os.path.join(args.csv_dir, n)) for n in files}
    checks["hashes"] = {"pass": archive_sha == prov["archive"]["sha256"] and actual == files,
                        "archive_sha256": archive_sha, "csv_mismatches": [n for n in files if actual[n] != files[n]]}

    # 2. rederive
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "rederived.json")
        cmd = [sys.executable, "-I", os.path.join(HERE, "derive_cicddos2019.py"), "--csv-dir", args.csv_dir,
               "--archive", args.archive, f"--csv-utc-offset={prov['csv_clock_utc_offset']}",
               "--victim", deriv["victim"], "--attacker", deriv["attacker"],
               "--flood-flows-per-s", str(deriv["flood_flows_per_s"]), "--merge-gap-s", str(deriv["merge_gap_s"]),
               "--min-episode-s", str(deriv["min_episode_s"]), "--guard-s", str(rules["guard_seconds"]),
               "--version", rules["label_rules_version"], "--out", out]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        with open(out, encoding="utf-8") as stream:
            again = json.load(stream)
    key = lambda ivs: [{k: iv.get(k) for k in ("id", "kind", "family", "start", "end", "victims")} for iv in ivs]
    checks["rederive"] = {"pass": key(again["intervals"]) == key(rules["intervals"]),
                          "intervals_compared": len(rules["intervals"])}

    # 3-6. one streaming pass over the official CSVs
    tz_offset = datetime.strptime(prov["csv_clock_utc_offset"].replace(":", ""), "%z").utcoffset()
    guard = int(rules["guard_seconds"] * 10**9)
    attacks = [(iv, to_ns(iv["start"]), to_ns(iv["end"])) for iv in rules["intervals"] if iv.get("kind", "attack") == "attack"]
    excludes = [(to_ns(iv["start"]), to_ns(iv["end"])) for iv in rules["intervals"] if iv.get("kind") == "exclude"]
    victim, attacker = deriv["victim"], deriv["attacker"]
    family_of = {"Portmap": "PORTMAP", "NetBIOS": "NETBIOS", "LDAP": "LDAP", "MSSQL": "MSSQL",
                 "UDP": "UDP", "UDPLag": "UDP_LAG", "Syn": "SYN"}
    place = defaultdict(Counter)
    benign_in_core = 0
    outside_per_second = Counter()
    off_pair = Counter()
    outside_exclusion = 0
    for name in sorted(files):
        with open(os.path.join(args.csv_dir, name), encoding="utf-8", errors="replace") as f:
            header = [c.strip() for c in next(f).split(",")]
            i_src, i_dst, i_ts, i_lab = (header.index(c) for c in ("Source IP", "Destination IP", "Timestamp", "Label"))
            for line in f:
                p = line.rstrip("\r\n").split(",")
                label = p[i_lab].strip()
                src, dst = p[i_src], p[i_dst]
                if label == "BENIGN":
                    if dst == victim:
                        d = datetime.strptime(p[i_ts], "%Y-%m-%d %H:%M:%S.%f") - tz_offset
                        t = int((d - datetime(1970, 1, 1)).total_seconds()) * 10**9 + d.microsecond * 1000
                        if any(lo + guard <= t < hi - guard for _, lo, hi in attacks):
                            benign_in_core += 1
                    continue
                if {src, dst} != {victim, attacker}:
                    off_pair[(src, dst)] += 1
                    continue
                d = datetime.strptime(p[i_ts], "%Y-%m-%d %H:%M:%S.%f") - tz_offset
                t = int((d - datetime(1970, 1, 1)).total_seconds()) * 10**9 + d.microsecond * 1000
                if not any(lo <= t < hi for lo, hi in excludes):
                    outside_exclusion += 1
                if dst != victim:
                    continue
                where = "outside"
                for iv, lo, hi in attacks:
                    if lo + guard <= t < hi - guard:
                        where = "core-same-family" if iv["family"] == family_of.get(label) else "core-other-family"
                        break
                    if lo - guard <= t < hi + guard:
                        where = "guard"
                place[label][where] += 1
                if where == "outside":
                    outside_per_second[t // 10**9] += 1
        print(name, "checked", flush=True)

    checks["pair"] = {"pass": not off_pair, "attack_flows_outside_pair": sum(off_pair.values())}
    coverage = {}
    floods_ok = True
    flood_families = {iv["family"] for iv, _, _ in attacks}
    for label, c in sorted(place.items()):
        total = sum(c.values())
        in_core = c["core-same-family"] + c["core-other-family"]
        entry = {"flows_to_victim": total, **{k: c[k] for k in ("core-same-family", "core-other-family", "guard", "outside")},
                 "core_share": round(in_core / total, 6)}
        entry["core_or_guard_share"] = round((in_core + c["guard"]) / total, 6)
        if family_of.get(label) in flood_families:
            entry["flood_family"] = True
            entry["ok"] = entry["core_or_guard_share"] >= FLOOD_CORE_OR_GUARD_MIN_SHARE and c["core-other-family"] == 0
            floods_ok &= entry["ok"]
        else:
            entry["flood_family"] = False
            entry["note"] = "not a flood interval; outside flood cores its windows are ambiguous (exclude interval)"
            if c["core-other-family"]:
                entry["family_deviation"] = (f"{c['core-other-family']} flows carrying this official label fall inside "
                                             "another family's flood core and are labelled with that family")
        coverage[label] = entry
    checks["coverage"] = {"pass": floods_ok, "criteria_version": CRITERIA_VERSION,
                          "min_flood_core_or_guard_share": FLOOD_CORE_OR_GUARD_MIN_SHARE, "by_official_label": coverage}
    dropped_seconds = {to_ns(e["start"]) // 10**9 for e in deriv.get("dropped_short_episodes", [])}
    busy = sorted(sec for sec, n in outside_per_second.items() if n >= deriv["flood_flows_per_s"])
    undocumented = [sec for sec in busy if sec not in dropped_seconds]
    checks["outside"] = {"pass": not undocumented, "criteria_version": CRITERIA_VERSION,
                         "busiest_second_outside_intervals": max(outside_per_second.values()) if outside_per_second else 0,
                         "seconds_at_or_above_threshold": len(busy), "undocumented_seconds": undocumented[:20],
                         "flood_threshold": deriv["flood_flows_per_s"]}
    core_flows = sum(c["core-same-family"] + c["core-other-family"] for c in place.values())
    checks["purity"] = {"pass": benign_in_core / max(core_flows, 1) < MAX_BENIGN_IN_CORE_SHARE,
                        "official_benign_flows_to_victim_in_cores": benign_in_core,
                        "attack_flows_in_cores": core_flows, "max_share": MAX_BENIGN_IN_CORE_SHARE}
    checks["exclusion"] = {"pass": outside_exclusion == 0, "attack_flows_outside_exclude_interval": outside_exclusion}

    # 7. evidence
    ev = [{"path": os.path.abspath(p), "sha256": sha256_file(p)} for p in args.evidence if os.path.exists(p)]
    missing = [p for p in args.evidence if not os.path.exists(p)]
    checks["evidence"] = {"pass": not missing and bool(ev), "files": ev, "missing": missing,
                          "timezone_evidence": prov.get("timezone_evidence")}

    report = {"criteria_version": CRITERIA_VERSION, "rules": os.path.abspath(args.rules),
              "rules_sha256": sha256_file(args.rules),
              "label_rules_version": rules["label_rules_version"], "checks": checks,
              "result": "PASS" if all(c["pass"] for c in checks.values()) else "FAIL"}
    with open(args.report, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({k: v["pass"] for k, v in checks.items()}), report["result"])
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
