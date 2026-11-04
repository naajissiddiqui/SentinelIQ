# Label rules

Ground truth for window datasets comes only from rule files in this folder,
written by a person from an **authoritative external source**. The format and
the labelling semantics are defined in `netsensor/labels.py`. There is
deliberately no rule file here yet.

## Status (2026-10-18)

| Dataset | Captures on disk | Authoritative label source on disk | Rule file |
|---|---|---|---|
| CIC-DDoS2019, 2018-11-03 ("03-11") | `C:\PCAP-03-11\` (146 files) | Official `CSV-03-11.zip` (SHA-256 `a81d8ce5…c263`), extracted to `C:\CSV-03-11\03-11\` (CRC32 of all 7 CSVs matches the ZIP) | `cicddos2019_0311_v1.json`, **verified 2026-10-18** by `verify_cicddos2019.py` (criteria v2: all 8 checks PASS; record and report hashes in its `provenance.verification`) |
| CIC-IDS2017, Friday | **No PCAP** | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (labels for a capture we do not have) | — |

Findings for 03-11 (reproduce with `derive_cicddos2019.py`; details in the rule file's provenance):
- The CSV timestamps are local time, UTC−03:00. This was measured, not assumed: 832,366 official flows
  matched netsensor flows on the identical 5-tuple at exactly +3 h, across all 7 CSV files.
- An official attack label means "flow between 172.16.0.5 and 192.168.50.4", named after the file's
  time slice. The attacker's low-rate background toward the victim is labelled attack all day, and a
  flood's first minute can carry the previous file's name (185,582 NetBIOS-flood flows say `Portmap`).
- The rule file therefore labels only the five flood cores (NETBIOS, LDAP, MSSQL, UDP, SYN) as attack.
  Every other victim or attacker window is ambiguous, including PORTMAP and UDP_LAG, which the flow
  labels cannot separate from the background. All other destinations are benign: the CSVs contain no
  attack flow to them.

Do not label CIC-DDoS2019 windows from the CIC-IDS2017 CSV, from attack
schedules quoted from memory, or from what the traffic looks like.

## Writing a rule file (CIC-DDoS2019 03-11)

1. Download the official `CSV-03-11` archive from the dataset publisher and record its SHA-256.
2. For each per-attack CSV, take the time span of its non-`BENIGN` rows, per victim address.
3. Establish the timezone of those timestamps from the dataset's documentation, and check it
   against the captures: the PCAP timestamps are UTC.
4. Write the file with an explicit UTC offset on every time, with `verified: true`,
   `verified_by` and `verified_on`, and list every source file with its SHA-256 under
   `provenance.source_files`.
5. Measure agreement before training: the fraction of flood windows (by packet rate)
   that fall inside labelled intervals, and labelled intervals with no traffic. Report it.

`build-dataset` refuses unverified rules unless `--allow-unverified-labels` is
passed. A dataset built that way is marked `usable_for_training: false`.
