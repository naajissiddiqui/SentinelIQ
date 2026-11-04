# SentinelIQ — Multi-Threat Implementation Plan

Scope: add **Privilege Escalation** and **Data Exfiltration** detection alongside the existing ransomware detector, add **MITRE ATT&CK** mapping, and extend the **CTI → blockchain verification** pipeline to all three attack types.

> **Read this first: the repository was not available when this plan was written.**
> No SentinelIQ checkout exists on this machine. I searched the user profile, `C:\src` and `C:\WeddAI`, and found no `CTIRegistry.sol` and no SentinelIQ folder. So **everything this plan says "exists" comes from the task brief, not from reading code.** File paths are written as `<agent>/…`, `<backend>/…`, `<dashboard>/…` and `<contracts>/…` placeholders. **Step 0 of Phase 1 is to check every row in §1 against the real repository** and replace each placeholder with a real path before anyone writes code.

---

## 1. Current architecture and gaps

| Component | Stated in brief (EXISTING, not verified) | Gap for this work |
|---|---|---|
| Telemetry | Sysmon on Windows endpoints | Sysmon config probably tuned for file activity only. It needs EIDs 1, 3, 8, 10, 13, 22. Some Windows Security log events are also needed (§2). |
| Python agent | Collects telemetry and runs detection | No rule engine for non-ransomware behaviour. No per-process network byte counts. |
| Ransomware model | XGBoost classifier | Single-class. **Keep it as it is.** Do not retrain it or relabel its output. |
| Backend + DB | Receives alerts and stores them | Alert schema is probably ransomware-shaped. It needs `attack_type`, `evidence[]`, `mitre[]` and a `confidence` tier. |
| Response policies | Ransomware response actions | Needs a policy per attack type. A new detector must never trigger an automatic kill/isolate action until it is tuned (§6). |
| Dashboard | Shows ransomware alerts | Needs an attack-type filter, MITRE chips and the CTI/verification status. |
| CTI + blockchain | `CTIRegistry.sol` on Polygon Amoy stores CTI hashes | Unknown whether it has access control, a duplicate check, events or a `verify` view. This decides §4.6. |

**Design principle:** the two new detectors are **rule-based plugins** that sit next to the XGBoost detector. All three detectors emit one shared `Alert` shape. Everything downstream (backend, CTI, chain, dashboard) works with that shared shape, so the ransomware path changes only by having its output wrapped in it.

---

## 2. Detection design

### 2.0 Shared alert model and confidence tiers

Every detector emits the following fields:
`attack_type`, `rule_id`, `confidence_tier`, `severity`, `risk_score (0–100)`, `host_id`, `process` (pid, image, cmdline, user, integrity), `evidence[]` (raw event refs + key fields), `mitre[]`, `first_seen`, `last_seen`.

There are three confidence tiers. This is how the plan separates *suspicious* from *confirmed*:

- **`suspicious`**: one weak indicator, such as an LOLBin making an outbound connection, or a process starting with High integrity.
- **`likely`**: two or more independent indicators from one process tree within a time window.
- **`confirmed`**: a definite state change is observed. For privilege escalation this means a child process runs at higher integrity or as SYSTEM, its parent ran at Medium, and the transition did not go through a legitimate elevation path. For exfiltration this means bytes from files that were read were *demonstrably* sent: a file read is followed by an outbound volume that matches the file size, to a destination on the deny-list or never seen before. Alerts should still say **"probable exfiltration"**. The agent cannot inspect payloads, so it never claims to have proven which data left.

**Risk score** = `base(rule) × tier multiplier (0.5 / 0.8 / 1.0)`, plus asset weight and user weight, capped at 100. Severity bands: Low < 40 ≤ Medium < 70 ≤ High < 90 ≤ Critical. Ransomware keeps its model probability, mapped onto the same 0–100 scale.

### 2.1 Privilege escalation

**Telemetry required**

| Source | Events | Why |
|---|---|---|
| Sysmon | **1** ProcessCreate (`IntegrityLevel`, `User`, `ParentImage`) | Detects a change in integrity level or user between parent and child |
| Sysmon | **13** RegistryValueSet | UAC-bypass keys and IFEO keys |
| Sysmon | **10** ProcessAccess to `lsass.exe` | Credential theft that usually comes before escalation |
| Sysmon | **8** CreateRemoteThread | Injection into a higher-privilege process |
| Security log | **4672** (special privileges at logon), **4688** with `TokenElevationType`, **4697** (service installed), **4698** (scheduled task created), **4720** (user created), **4732** (member added to a local group) | Elevation and account changes. Requires audit policy plus "include command line in process creation events". |
| System log | **7045** (service installed) | Backup for 4697 |

**Rules (start set)**

| ID | Rule | Tier |
|---|---|---|
| PE-01 | The child process has `IntegrityLevel` High/System, its parent is Medium, and the parent is not `consent.exe` / `svchost.exe (Appinfo)`. | confirmed |
| PE-02 | A Sysmon 13 write to `HKCU\Software\Classes\ms-settings\shell\open\command` or `…\mscfile\shell\open\command`, followed within 60 s by `fodhelper.exe` / `eventvwr.exe` / `computerdefaults.exe` | likely (confirmed if PE-01 also fires) |
| PE-03 | A new service (4697/7045) or a SYSTEM scheduled task (4698) whose binary is in a user-writable path (`%TEMP%`, `%APPDATA%`, `Users\Public`) | likely |
| PE-04 | 4732: an account is added to `Administrators` by a non-admin-tool parent, or a 4720 + 4732 pair within 10 min | likely |
| PE-05 | Sysmon 10 on `lsass.exe` with `GrantedAccess` that includes `0x1010` / `0x1410`, from a process that is not a known security product | suspicious |
| PE-06 | A Sysmon 13 write to `HKLM\…\Image File Execution Options\*\Debugger` | likely |

Suppression: an allow-list by signed image hash and parent (installers, SCCM/Intune, the EDR itself). Every rule is defined in YAML with `rule_id`, conditions, window, tier, base score and mitre[], so tuning does not need a code change.

### 2.2 Data exfiltration

**Telemetry required**

| Source | Events / data | Why |
|---|---|---|
| Sysmon | **3** NetworkConnect (dest IP and port, process) | Who connects to where. **Note: it contains no byte counts.** |
| Sysmon | **22** DNSQuery | Domains contacted; DNS-tunnelling patterns |
| Sysmon | **1** ProcessCreate | Archivers and transfer tools, with their command lines |
| Sysmon | **11** FileCreate | Archives created in staging directories |
| Agent (new) | **Per-process bytes sent**. Preferred source: the ETW `Microsoft-Windows-Kernel-Network` provider (TCP/UDP send events with size and PID). Fallback: per-interval totals from `psutil` plus the connection table. | Volume is the core signal. The fallback cannot attribute bytes to one process, so rules that use it are capped at `suspicious`. |
| Agent (new) | File-read volume per process. Sysmon has **no** file-read event. Use ETW `Microsoft-Windows-Kernel-File`, or enable object-access auditing (4663) on sensitive folders only. | Needed to link file access to the transfer |

**Rules (start set)**

| ID | Rule | Tier |
|---|---|---|
| EX-01 | A process sends more than N MB (default 100 MB/10 min) to one external destination, and that volume is more than 5× the host's 7-day baseline for that hour | suspicious |
| EX-02 | An archiver (`7z`, `rar`, `tar`, `Compress-Archive`, `makecab`) writes an archive in `%TEMP%`/`Users\Public`, and the same process tree then sends ≥ 80% of the archive size outbound within 30 min | likely |
| EX-03 | A known transfer tool (`rclone`, `curl -T/--upload-file`, `scp`, `ftp`, `bitsadmin /upload`) or a PowerShell `Invoke-WebRequest -Method Put/Post -InFile` connects to a cloud-storage or never-seen domain | likely |
| EX-04 | DNS: more than X queries/min to one parent domain, with long (> 50 chars) high-entropy subdomain labels | suspicious → likely if sustained > 10 min |
| EX-05 | Correlation: a process reads > N files or > N MB under a sensitive path (configurable list), **and** that same process tree triggers EX-01 or EX-03 within the window | **confirmed (probable exfiltration)** |
| EX-06 | Ransomware detector fires on a host where EX-01/EX-02 fired in the previous 24 h → raise both alerts and link them (double extortion) | inherits the higher tier |

**Correlation method:** the agent keeps a rolling 30-minute in-memory table keyed by **process GUID** (Sysmon `ProcessGuid`, which survives PID reuse). The table holds `files_read_bytes`, `archives_written` and `bytes_sent_by_dest`, plus the parent GUID chain. Rules query this table. Network activity on its own **never** goes above `suspicious`.

---

## 3. MITRE ATT&CK mapping

Rule: **techniques are attached per rule, based on the evidence that fired.** They are never attached because of the attack-type label. If an alert fires only PE-05, it gets T1003.001 and nothing else.

> **Verify all IDs against https://attack.mitre.org (Enterprise) before merging.** Pin the ATT&CK version in `mitre_map.yaml` (`attack_version: "<current>"`). The IDs below were checked against the Enterprise matrix as of mid-2026. Sub-technique names do change between versions; for example, the DLL-hijack sub-techniques under T1574 were consolidated, so this plan deliberately avoids them.

| Category | Rule | Tactic | Technique |
|---|---|---|---|
| Ransomware (existing model) | encryption behaviour | Impact TA0040 | T1486 Data Encrypted for Impact |
| | shadow-copy / backup deletion (if the agent sees `vssadmin`/`wbadmin`) | Impact TA0040 | T1490 Inhibit System Recovery |
| | mass file enumeration (if present in evidence) | Discovery TA0007 | T1083 File and Directory Discovery |
| Privilege escalation | PE-01 (generic) | Privilege Escalation TA0004 | T1068 Exploitation for Privilege Escalation, **only** if no more specific rule matched; otherwise no technique, the tactic alone |
| | PE-02 | TA0004 / Defense Evasion TA0005 | T1548.002 Abuse Elevation Control Mechanism: Bypass UAC |
| | PE-03 (service) | TA0004 / Persistence TA0003 | T1543.003 Create or Modify System Process: Windows Service |
| | PE-03 (task) | TA0004 / TA0003 / Execution TA0002 | T1053.005 Scheduled Task/Job: Scheduled Task |
| | PE-04 | TA0003 / TA0004 | T1098 Account Manipulation (+ T1136.001 Create Account: Local Account when 4720 is present) |
| | PE-05 | Credential Access TA0006 | T1003.001 OS Credential Dumping: LSASS Memory |
| | PE-06 | TA0004 / TA0003 | T1546.012 Event Triggered Execution: Image File Execution Options Injection |
| | Sysmon 8 into a higher-integrity process | TA0004 / TA0005 | T1055 Process Injection |
| Data exfiltration | EX-02 archive step | Collection TA0009 | T1560.001 Archive Collected Data: Archive via Utility; T1074.001 Local Data Staging |
| | EX-05 file-read step | Collection TA0009 | T1005 Data from Local System |
| | EX-01/EX-03 to a cloud-storage domain | Exfiltration TA0010 | T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| | EX-03 via FTP/SCP/plain protocol | TA0010 | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (T1048 if the protocol is unknown) |
| | EX-01 to a destination that is already an active C2 indicator | TA0010 | T1041 Exfiltration Over C2 Channel |
| | EX-04 | TA0010 | T1048 Exfiltration Over Alternative Protocol (DNS). Add T1071.004 (C2 TA0011) only if bidirectional C2 is evidenced. |

Each `mitre[]` entry stores `{tactic_id, technique_id, name, attack_version, evidence_ref}`, where `evidence_ref` points at the `evidence[]` items that justify it.

---

## 4. CTI, blockchain and verification

### 4.1 Flow
`Alert(s)` → **CTI builder** (backend) → `draft` → analyst **review/approve** (dashboard) → `approved` (now immutable) → **canonicalise + SHA-256** → store the report off-chain → **publish hash** to the existing `CTIRegistry.sol` on Polygon Amoy → record `tx_hash`, `block_number` → `anchored` → **verify** on demand.

### 4.2 CTI schema (`cti_report` v1)
```json
{
  "schema_version": "1.0",
  "report_id": "uuid-v4",
  "attack_type": "ransomware | privilege_escalation | data_exfiltration",
  "title": "string",
  "detected_at": "RFC3339 UTC", "first_seen": "...", "last_seen": "...",
  "severity": "low|medium|high|critical", "risk_score": 0,
  "confidence_tier": "suspicious|likely|confirmed",
  "detector": {"type": "xgboost|rule", "id": "PE-02", "version": "1.0.0"},
  "mitre": [{"tactic_id": "TA0004", "technique_id": "T1548.002", "attack_version": "x", "evidence_ref": ["e1"]}],
  "evidence": [{"id": "e1", "source": "sysmon", "event_id": 13, "time": "...", "fields": {}}],
  "indicators": [{"type": "sha256|domain|ipv4|registry_key", "value": "..."}],
  "host_ref": "pseudonymous id (HMAC of host_id)",
  "approval": {"approved_by": "user id", "approved_at": "..."},
  "supersedes": null
}
```
Required fields: everything except `indicators` and `supersedes`. Validate the report with a JSON Schema in the backend before approval.

### 4.3 Canonical serialisation
- Use **RFC 8785 JSON Canonicalization Scheme (JCS)**: sorted keys, no whitespace, fixed number formatting, UTF-8. Use a library implementation, not `json.dumps(sort_keys=True)`, because float and unicode handling differ.
- Normalise before canonicalising: timestamps go to UTC `Z` with fixed precision, `risk_score` becomes an integer, and arrays are sorted by `id`/`technique_id`.
- The hash covers the **whole approved report minus nothing**. Store the exact canonical bytes as well, not just the object, so verification never depends on re-serialisation.
- `report_hash = SHA-256(canonical_bytes)`, written on-chain as `bytes32`.

### 4.4 Publication (backend `chain_publisher`)
- One server-side signer key, held in env/secret store and never on endpoints. Use web3.py or ethers to call the existing contract's store function.
- States: `approved → submitting → submitted(tx_hash) → anchored(block, confirmations ≥ N) | failed(reason)`.
- **Failed tx / timeout**: re-check the receipt by `tx_hash` first. Only resubmit if the hash is not on-chain. Manage the nonce in the DB under a lock, and use bounded retries with fee bump.
- **Duplicate submission**: the backend refuses if `report_hash` is already `anchored`. If the contract reverts on a duplicate, read the existing record and mark the report `anchored` (idempotent). If the contract does **not** reject duplicates, the backend check is the guard.
- **Unauthorized publisher**: only the backend signer address may write. If the contract has `onlyOwner`/role control, use it. If not, verification checks that the record's `msg.sender` (from the event or tx) is on an allow-list of publisher addresses in config.
- **Modified reports**: approved reports are immutable. A correction creates a new report with `supersedes = <old report_id>`, which gets a new hash and a new anchor.

### 4.5 Verification
`GET /cti/{report_id}/verify` loads the stored canonical bytes and recomputes SHA-256. It then reads the on-chain record (contract view, or event log by tx hash) and returns `{match, on_chain_hash, recomputed_hash, tx_hash, block, publisher, publisher_authorised}`. It reports **`tampered`** if the hashes differ, **`unanchored`** if there is no record, and **`untrusted_publisher`** if the sender is not allow-listed. Also re-canonicalise the stored JSON object and compare it with the stored bytes, to catch DB-level edits.

### 4.6 On-chain vs off-chain; contract changes
- **On-chain only**: `report_hash`, an opaque `report_id` (or its hash), and the timestamp. **Never** hostnames, users, IPs, file paths, evidence or the full report. Amoy is a public chain.
- **Off-chain**: the full report and its canonical bytes, in the backend DB/object store, access-controlled and encrypted at rest. `attack_type` stays off-chain, so **the contract does not need to know about the new types.**
- **Contract decision:** reuse `CTIRegistry.sol` unchanged **if** it stores a `bytes32` hash and lets anyone read it back. Redeploy only if it has **no way to read a hash back** (no getter and no event). A missing access-control or duplicate check is handled in the backend (§4.4) and is documented as a known weakness. It is not on its own a reason to redeploy.

---

## 5. Files and modules (placeholders; resolve in Phase 1 step 0)

| Action | Path | Purpose |
|---|---|---|
| Modify | `<sysmon>/sysmonconfig.xml` | Enable EIDs 1, 3, 8, 10, 13, 22 with includes for the keys/paths above |
| Create | `<agent>/collectors/etw_network.py`, `etw_file.py` | Per-process bytes sent and file-read volume |
| Create | `<agent>/correlation/process_state.py` | Rolling process-GUID state table |
| Create | `<agent>/detectors/rules_engine.py` + `rules/privesc.yaml`, `rules/exfil.yaml` | Rule engine and rule definitions |
| Modify | `<agent>/detectors/ransomware*.py` | Wrap output in the shared `Alert` shape only. **No model change.** |
| Create | `<agent>/mitre/mitre_map.yaml` | rule_id → techniques, pinned ATT&CK version |
| Modify | `<backend>/models/alert*` (+ DB migration) | Add `attack_type`, `confidence_tier`, `evidence`, `mitre`. Existing rows default to `ransomware`. |
| Create | `<backend>/cti/builder.py`, `schema/cti_report_v1.json`, `canonical.py` | Build, validate and canonicalise reports |
| Modify/Create | `<backend>/blockchain/publisher.py`, `verifier.py` | Extend the existing publisher if there is one; state machine, retries, verify |
| Modify | `<backend>/response/policies*` | Per-attack-type policies, alert-only by default for the new types |
| Modify | `<dashboard>/…` alert list, alert detail, CTI view | Attack-type filter, MITRE chips, approve button, verify badge |
| Unchanged (target) | `<contracts>/CTIRegistry.sol` | See §4.6 |

---

## 6. Implementation phases and dependencies

1. **Phase 1 – Foundations.** Step 0: inspect the repo and fill in §1/§5. Then: shared `Alert` schema, DB migration, the ransomware output wrapper, and a regression test proving ransomware alerts are unchanged.
2. **Phase 2 – Telemetry.** Sysmon config, audit policy, ETW collectors, the process-state table. *Depends on 1.*
3. **Phase 3 – Detectors.** Rule engine, PE rules, EX rules, the MITRE map. Run in **alert-only mode** for at least one week on lab hosts to tune the allow-lists. *Depends on 2.*
4. **Phase 4 – CTI pipeline.** Builder, schema, JCS hashing, approval workflow. *Depends on 1; can run in parallel with 2–3 using ransomware alerts.*
5. **Phase 5 – Chain.** Contract audit (§4.6), publisher state machine, verifier. *Depends on 4.*
6. **Phase 6 – Dashboard and response policies.** *Depends on 3 and 5.* Enable automatic response for the new types only after the tuning results are reviewed.

---

## 7. Testing and acceptance criteria

**Safe test scenarios (isolated lab VM only, nothing destructive):**
- *PE*: open an elevated `cmd` via "Run as administrator" (expect **no** confirmed PE-01, because the path is legitimate). Run the Atomic Red Team tests for T1548.002 (fodhelper registry key; revert it afterwards), T1543.003 (create a service pointing at `%TEMP%\benign.exe`), and T1098 (add a test user to Administrators, then remove them). Open an LSASS handle with a benign tool, using the Atomic test for T1003.001 on a lab VM with no real credentials.
- *EX*: create 200 MB of dummy files and `7z` them into `%TEMP%`, then upload to a lab HTTP sink you control (EX-02/EX-05). Use `curl -T` to the same sink (EX-03). Use a DNS-tunnel simulator against a lab domain (EX-04). Negative control: a large OneDrive/Windows Update download must **not** fire.
- *Ransomware regression*: replay the existing ransomware test set and confirm the same verdicts and scores.

**Unit/integration tests:** a test for each rule (positive + negative fixture made from recorded event JSON); MITRE-map tests (each alert's techniques ⊆ techniques of the rules that fired); JCS golden vectors (the same report with different key order or whitespace gives the same hash; changing one field changes it); a publisher test against a local Hardhat/Anvil node (success, revert, timeout→receipt recovery, duplicate, wrong signer); verifier tests (match, tampered DB row, unanchored, untrusted publisher).

**Acceptance criteria**

| Feature | Accepted when |
|---|---|
| Ransomware preserved | Identical verdicts on the existing test set. No model file changed. |
| PE detector | All 4 Atomic scenarios alert with the correct rule, tier and technique. The legitimate elevation does not reach `confirmed`. ≤ 2 false positives/host/day during the tuning week. |
| EX detector | EX-02/03/05 fire on the lab scenarios. The negative controls stay silent. No alert reaches `confirmed` on network evidence alone. |
| MITRE | Every technique on every alert has an `evidence_ref`. All IDs resolve on attack.mitre.org for the pinned version. |
| CTI | Every approved report validates against the schema. The hash is reproducible across two machines. |
| Chain | An approved report is anchored with `tx_hash` stored. A retry never double-anchors. No PII appears in tx data or events. |
| Verify | It returns `match` for an untouched report and `tampered` after one byte of the stored report is edited. |
| Dashboard | You can filter by the 3 attack types. Alert detail shows evidence, tier, score and MITRE chips that link to attack.mitre.org. The CTI view shows approval state, tx link (Amoy explorer) and verify result. |

---

## 8. Risks, assumptions and unresolved questions

**Risks.**
- Without ETW, the agent cannot attribute network bytes to a process, so exfiltration detection is weak. Collecting ETW needs admin rights and adds CPU cost.
- Rules will produce false positives before they are tuned.
- Object-access auditing (4663) is noisy if scoped too widely.
- Amoy is a testnet: it can be reset or deprecated, so it is not durable evidence.
- If one backend signer key is lost or leaked, all anchors are affected.

**Assumptions.**
- Endpoints are Windows with Sysmon already installed.
- The agent runs with enough privilege to read the Security log and ETW.
- `CTIRegistry.sol` stores a `bytes32` hash.
- There is no labelled privilege-escalation or exfiltration training data, so the new detectors are rule-based.

**Unresolved (answer in Phase 1 step 0).**
1. Where is the SentinelIQ repo? What are the actual agent, backend, DB and dashboard stacks?
2. What exactly is `CTIRegistry.sol`'s interface? Specifically: its getter, events, access control and duplicate handling.
3. Is there an existing publisher module, signer key handling or CTI format to extend?
4. Where are reports stored off-chain today (DB, IPFS, other)? Has anything sensitive already been published?
5. Which folders count as "sensitive" for EX-05, and who approves CTI reports?
6. Is automatic response allowed for the new attack types at all, or alert-only permanently?
