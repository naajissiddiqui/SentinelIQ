"""
privilege_escalation.py
=======================
Rule-based privilege escalation detector for SentinelIQ (alert-only).

Consumes normalized events from SysmonReader / WindowsEventLogReader
({record_id, timestamp, event_id, pid, process_name, image, data, [channel]}).

Rules
-----
PE-01  Unexpected privileged process execution
       (Sysmon 1: High/System integrity image in user-writable path, or SYSTEM
        shell / whoami spawned by a non-system-manager parent)
PE-02  Suspicious parent-child chain involving elevated execution
       (Sysmon 1: Medium/Low parent -> SYSTEM child; Office/script host or
        service-account host -> elevated shell)
PE-03  Account / privileged-group membership changes
       (Sysmon 1 net/PowerShell command lines; Security 4720, 4728, 4732, 4756)
PE-04  Service / scheduled-task creation with elevated execution
       (Sysmon 1 sc/schtasks/New-Service/Register-ScheduledTask; Sysmon 13
        Services\\*\\ImagePath; System 7045; Security 4697, 4698)
PE-05  Known privilege-escalation / UAC-bypass indicators
       (Sysmon 12/13 UAC hijack keys; Sysmon 1 auto-elevate binary execution
        after hijack or spawning shells; known PE tooling)
PE-06  Suspicious security-related registry changes
       (Sysmon 12/13/14: IFEO, SilentProcessExit, UAC policy, Winlogon, LSA,
        Defender tamper)

Confidence tiers: 'suspicious' | 'likely' | 'confirmed'.
The detector never takes response actions; it only returns alert dicts.
"""

import re
import socket
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from mitre_mapper import map_mitre_techniques


ATTACK_TYPE = "PRIVILEGE_ESCALATION"
DEDUP_WINDOW_SECONDS = 300
UAC_HIJACK_CORRELATION_SECONDS = 120
# Alerts of the same rule within this window are one attack sequence and are
# merged into a single alert (covers 2-3 agent polls at the 3s step interval).
GROUP_HOLD_SECONDS = 8
# After a group is reported, further alerts of the same rule are suppressed for
# this long unless they carry a higher risk score (prevents repeat alerts).
GROUP_COOLDOWN_SECONDS = 60

USER_WRITABLE_PATHS = (
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\windows\\temp\\",
    "\\downloads\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
)

SHELLS_AND_LOLBINS = (
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "whoami.exe",
    "net.exe", "net1.exe",
)

# Parents that legitimately start SYSTEM shells (service manager, task host, installers, mgmt agents)
SYSTEM_MANAGER_PARENTS = (
    "services.exe", "svchost.exe", "msiexec.exe", "ccmexec.exe", "wmiprvse.exe",
    "taskhostw.exe", "trustedinstaller.exe", "tiworker.exe", "wininit.exe",
    "smss.exe", "csrss.exe", "msmpeng.exe", "mpcmdrun.exe", "sihost.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
)

OFFICE_AND_SCRIPT_HOSTS = (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "mspub.exe", "onenote.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "acrord32.exe", "acrobat.exe",
)

# Service-account processes commonly abused for token impersonation ("potato" attacks)
SERVICE_ACCOUNT_HOSTS = (
    "w3wp.exe", "sqlservr.exe", "spoolsv.exe", "httpd.exe", "nginx.exe",
    "php-cgi.exe", "tomcat.exe", "tomcat9.exe", "java.exe", "iisexpress.exe",
)

AUTO_ELEVATE_BINARIES = (
    "fodhelper.exe", "eventvwr.exe", "computerdefaults.exe", "sdclt.exe",
    "slui.exe", "cmstp.exe", "wsreset.exe", "changepk.exe", "dccw.exe",
)

UAC_HIJACK_KEYS = (
    "\\software\\classes\\ms-settings\\shell\\open\\command",
    "\\software\\classes\\mscfile\\shell\\open\\command",
    "\\software\\classes\\exefile\\shell\\runas\\command",
    "\\software\\classes\\folder\\shell\\open\\command",
    "\\software\\classes\\launcher.systemsettings\\shell\\open\\command",
    "\\software\\classes\\appx82a6gwre4fdg3bt635tn5ctqjf8msdd2\\shell\\open\\command",
    "\\software\\microsoft\\windows\\currentversion\\app paths\\control.exe",
    "\\environment\\windir",
)

# (pattern in lowercased image/command line, label, extra MITRE techniques)
KNOWN_PE_TOOLS: Tuple[Tuple[str, str, List[str]], ...] = (
    ("token::elevate", "Mimikatz token::elevate", ["T1134.001"]),
    ("privilege::debug", "Mimikatz privilege::debug", []),
    ("mimikatz", "Mimikatz", []),
    ("printspoofer", "PrintSpoofer", ["T1134.001"]),
    ("juicypotato", "JuicyPotato", ["T1134.001"]),
    ("roguepotato", "RoguePotato", ["T1134.001"]),
    ("sweetpotato", "SweetPotato", ["T1134.001"]),
    ("godpotato", "GodPotato", ["T1134.001"]),
    ("efspotato", "EfsPotato", ["T1134.001"]),
    ("badpotato", "BadPotato", ["T1134.001"]),
    ("localpotato", "LocalPotato", ["T1134.001"]),
    ("akagi", "UACMe (Akagi)", ["T1548.002"]),
    ("uacme", "UACMe", ["T1548.002"]),
    ("incognito", "Incognito token tool", ["T1134.001"]),
    ("getsystem", "getsystem", ["T1134.001"]),
)

PRIVILEGED_GROUPS = (
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "backup operators", "account operators", "server operators", "print operators",
    "remote desktop users", "remote management users", "hyper-v administrators",
    "dnsadmins", "group policy creator owners",
)
PRIVILEGED_GROUP_SIDS = ("s-1-5-32-544", "s-1-5-32-551", "s-1-5-32-548", "s-1-5-32-549",
                         "s-1-5-32-550", "s-1-5-32-555", "s-1-5-32-580")

# (TargetObject substring, value predicate on Details or None, title, risk, tier, extra MITRE)
SECURITY_REGISTRY_RULES = (
    ("\\policies\\system\\enablelua", lambda d: _dword(d) == 0,
     "UAC disabled (EnableLUA=0)", 88, "likely", ["T1548.002"]),
    ("\\policies\\system\\consentpromptbehavioradmin", lambda d: _dword(d) == 0,
     "UAC admin consent prompt disabled", 80, "likely", ["T1548.002"]),
    ("\\policies\\system\\localaccounttokenfilterpolicy", lambda d: _dword(d) == 1,
     "Remote UAC token filtering disabled", 72, "suspicious", ["T1548.002"]),
    ("\\silentprocessexit\\", lambda d: True,
     "SilentProcessExit monitor process registered", 82, "likely", ["T1546.012"]),
    ("\\winlogon\\userinit", lambda d: d is not None and d.strip().lower().rstrip(",") not in
     ("c:\\windows\\system32\\userinit.exe",),
     "Winlogon Userinit modified", 85, "likely", ["T1547.004"]),
    ("\\winlogon\\shell", lambda d: d is not None and d.strip().lower() not in ("explorer.exe",),
     "Winlogon Shell modified", 85, "likely", ["T1547.004"]),
    ("\\control\\lsa\\runasppl", lambda d: _dword(d) == 0,
     "LSA protection (RunAsPPL) disabled", 82, "likely", ["T1562.001"]),
    ("\\control\\lsa\\security packages", lambda d: True,
     "LSA Security Packages modified", 85, "likely", ["T1547.005"]),
    ("\\control\\lsa\\authentication packages", lambda d: True,
     "LSA Authentication Packages modified", 85, "likely", ["T1547.002"]),
    ("\\control\\lsa\\notification packages", lambda d: True,
     "LSA Notification Packages modified", 80, "likely", ["T1547.002"]),
    ("\\windows defender\\disableantispyware", lambda d: _dword(d) == 1,
     "Microsoft Defender disabled via registry", 80, "likely", ["T1562.001"]),
    ("\\real-time protection\\disablerealtimemonitoring", lambda d: _dword(d) == 1,
     "Defender real-time monitoring disabled via registry", 80, "likely", ["T1562.001"]),
)

ACCESSIBILITY_BINARIES = ("sethc.exe", "utilman.exe", "osk.exe", "narrator.exe",
                          "magnify.exe", "displayswitch.exe", "atbroker.exe")


def _dword(details: Optional[str]) -> Optional[int]:
    """Parses Sysmon 'DWORD (0x00000001)' detail strings."""
    if not details:
        return None
    m = re.search(r"0x([0-9a-fA-F]+)", details)
    if m:
        return int(m.group(1), 16)
    try:
        return int(details.strip())
    except ValueError:
        return None


def _basename(path: Optional[str]) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].strip().lower()


def _in_writable_path(text: str) -> bool:
    t = (text or "").lower()
    return any(p in t for p in USER_WRITABLE_PATHS)


def _is_system_user(user: Optional[str]) -> bool:
    u = (user or "").strip().lower()
    return u in ("nt authority\\system", "system", "s-1-5-18") or u.endswith("\\system")


def _severity(risk: int) -> str:
    # Mirrors backend severityFromRiskScore so the agent console matches the UI
    if risk >= 90:
        return "CRITICAL"
    if risk >= 70:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    return "LOW"


_TIER_CONFIDENCE = {"suspicious": 0.55, "likely": 0.75, "confirmed": 0.92}
_TIER_RANK = {"suspicious": 0, "likely": 1, "confirmed": 2}


class PrivilegeEscalationDetector:
    def __init__(
        self,
        hostname: Optional[str] = None,
        dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
        hold_seconds: float = GROUP_HOLD_SECONDS,
        cooldown_seconds: float = GROUP_COOLDOWN_SECONDS,
        clock=time.monotonic,
    ):
        self.hostname = hostname or socket.gethostname()
        self.dedup_window_seconds = dedup_window_seconds
        self.hold_seconds = hold_seconds
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock
        self._recent_uac_reg_writes: List[Dict[str, Any]] = []
        # ProcessGuid -> {image, integrity, user}, bounded LRU
        self._proc_cache: "OrderedDict[str, Dict[str, str]]" = OrderedDict()
        self._seen: Dict[str, float] = {}
        self._seq = 0
        # group key -> {"alerts": [...], "deadline": t}
        self._pending: Dict[str, Dict[str, Any]] = {}
        # group key -> (reported at, risk score)
        self._reported: Dict[str, Tuple[float, int]] = {}
        self.suppressed_count = 0

    # ── Public API ──────────────────────────────────────────────────────────

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluates events and returns alerts whose correlation window has closed.
        Call every poll (even with no events) so held alerts are released on time."""
        for event in events:
            try:
                for alert in self.evaluate_event(event):
                    self._add_to_group(alert)
            except Exception as e:  # never let a malformed event break the agent loop
                print(f"[PE Detector] Failed to evaluate event {event.get('record_id')}: {e}")
        return self._release(force=False)

    def flush_all(self) -> List[Dict[str, Any]]:
        """Releases all held alerts immediately (agent shutdown)."""
        return self._release(force=True)

    # ── Correlation / grouping ─────────────────────────────────────────────

    def _add_to_group(self, alert: Dict[str, Any]) -> None:
        # The detector runs per host, so one group per rule family = one attack sequence
        key = alert["rule_id"]
        now = self._clock()
        if key in self._pending:
            self._pending[key]["alerts"].append(alert)
            return
        last = self._reported.get(key)
        if last and now - last[0] < self.cooldown_seconds and alert["risk_score"] <= last[1]:
            self.suppressed_count += 1
            return
        self._pending[key] = {"alerts": [alert], "deadline": now + self.hold_seconds}

    def _release(self, force: bool) -> List[Dict[str, Any]]:
        now = self._clock()
        out: List[Dict[str, Any]] = []
        for key in list(self._pending):
            group = self._pending[key]
            if force or now >= group["deadline"]:
                del self._pending[key]
                merged = self._merge(group["alerts"])
                self._reported[key] = (now, merged["risk_score"])
                out.append(merged)
        out.sort(key=lambda a: str(a["timestamp"]))
        return out

    @staticmethod
    def _strip_private(alert: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in alert.items() if not k.startswith("_")}

    def _merge(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        if len(alerts) == 1:
            single = self._strip_private(alerts[0])
            single["correlated_events"] = 1
            return single

        top = max(alerts, key=lambda a: (_TIER_RANK.get(a["confidence_tier"], 0), a["risk_score"]))
        merged = dict(top)
        merged["risk_score"] = max(a["risk_score"] for a in alerts)
        merged["severity"] = _severity(merged["risk_score"])
        merged["confidence"] = _TIER_CONFIDENCE.get(merged["confidence_tier"], 0.6)
        merged["timestamp"] = min((a["timestamp"] for a in alerts), key=str)
        merged["title"] = self._sequence_title(alerts, top)
        merged["correlated_events"] = len(alerts)

        evidence, ev_ids = [], set()
        indicators, ind_keys = [], set()
        mitre: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        for a in alerts:
            for ev in a["evidence"]:
                if ev["id"] not in ev_ids:
                    ev_ids.add(ev["id"])
                    evidence.append(ev)
            for ind in a["indicators"]:
                k = (ind["type"], ind["description"])
                if k not in ind_keys:
                    ind_keys.add(k)
                    indicators.append(ind)
            for m in a["mitre"]:
                if m["techniqueId"] in mitre:
                    refs = mitre[m["techniqueId"]]["evidenceRef"]
                    refs.extend(r for r in m.get("evidenceRef", []) if r not in refs)
                else:
                    mitre[m["techniqueId"]] = {**m, "evidenceRef": list(m.get("evidenceRef", []))}
        indicators.append({
            "type": "CORRELATION",
            "description": f"{len(alerts)} related {top['rule_id']} events from the same attack sequence grouped into one alert",
            "observedAt": indicators[0]["observedAt"] if indicators else "",
        })
        merged["evidence"] = evidence
        merged["indicators"] = indicators
        merged["mitre"] = list(mitre.values())
        return self._strip_private(merged)

    @staticmethod
    def _sequence_title(alerts: List[Dict[str, Any]], top: Dict[str, Any]) -> str:
        tags = {a.get("_tag") for a in alerts}
        details = {a.get("_tag"): a.get("_detail") for a in alerts if a.get("_detail")}
        if "uac_reg" in tags and tags & {"uac_exec", "uac_child"}:
            binary = details.get("uac_exec") or details.get("uac_child") or "auto-elevate binary"
            return f"UAC bypass via {binary}: registry hijack followed by auto-elevated execution"
        if "user" in tags and "group" in tags:
            account = details.get("user") or "new account"
            return f"Account '{account}' created and added to privileged group '{details.get('group', 'administrators')}'"
        return f"{top['title']} (+{len(alerts) - 1} correlated events)"

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        channel = (event.get("channel") or "sysmon").lower()
        event_id = event.get("event_id")
        candidates: List[Optional[Dict[str, Any]]] = []

        if channel == "sysmon":
            if event_id == 1:
                self._cache_process(event)
                candidates += [
                    self._pe01_privileged_process(event),
                    self._pe02_parent_child(event),
                    self._pe03_account_cmdline(event),
                    self._pe04_service_task_cmdline(event),
                    *self._pe05_process_indicators(event),
                ]
            elif event_id in (12, 13, 14):
                candidates += [
                    self._pe04_service_imagepath(event),
                    self._pe05_uac_registry(event),
                    self._pe06_security_registry(event),
                ]
        elif channel == "security":
            if event_id in (4720, 4728, 4732, 4756):
                candidates.append(self._pe03_security_log(event))
            elif event_id in (4697, 4698):
                candidates.append(self._pe04_event_log(event))
        elif channel == "system" and event_id == 7045:
            candidates.append(self._pe04_event_log(event))

        return [a for a in candidates if a and not self._is_duplicate(a)]

    # ── Helpers ────────────────────────────────────────────────────────────

    def _cache_process(self, event: Dict[str, Any]) -> None:
        data = event.get("data") or {}
        guid = data.get("ProcessGuid")
        if not guid:
            return
        self._proc_cache[guid] = {
            "image": data.get("Image") or "",
            "integrity": (data.get("IntegrityLevel") or "").lower(),
            "user": data.get("User") or "",
        }
        self._proc_cache.move_to_end(guid)
        while len(self._proc_cache) > 5000:
            self._proc_cache.popitem(last=False)

    def _is_duplicate(self, alert: Dict[str, Any]) -> bool:
        now = self._clock()
        self._seen = {k: t for k, t in self._seen.items() if now - t < self.dedup_window_seconds}
        key = alert.pop("_dedup_key")
        if key in self._seen:
            return True
        self._seen[key] = now
        return False

    def _build_alert(
        self,
        event: Dict[str, Any],
        rule_id: str,
        mitre_key: str,
        title: str,
        tier: str,
        risk: int,
        description: str,
        indicators: List[Tuple[str, str]],
        evidence_fields: Dict[str, Any],
        dedup_key: str,
        extra_techniques: Optional[List[str]] = None,
        related_evidence: Optional[List[Dict[str, Any]]] = None,
        tag: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        data = event.get("data") or {}
        ts = event.get("timestamp") or datetime.now(timezone.utc)
        ts_iso = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        self._seq += 1
        ev_id = f"ev-{rule_id.lower()}-{int(time.time() * 1000)}-{self._seq}"
        channel = (event.get("channel") or "sysmon").lower()

        user = data.get("User") or data.get("SubjectUserName") or ""
        if data.get("SubjectDomainName") and data.get("SubjectUserName"):
            user = f"{data['SubjectDomainName']}\\{data['SubjectUserName']}"
        confidence = _TIER_CONFIDENCE.get(tier, 0.6)

        context = {
            "Host": self.hostname,
            "User": user,
            "ProcessId": event.get("pid"),
            "Image": event.get("image") or data.get("Image") or "",
            "CommandLine": data.get("CommandLine", ""),
            "ParentImage": data.get("ParentImage", ""),
            "ParentCommandLine": data.get("ParentCommandLine", ""),
            "IntegrityLevel": data.get("IntegrityLevel", ""),
            "RuleId": rule_id,
            "Confidence": confidence,
            "RiskScore": risk,
        }
        context.update(evidence_fields)
        context = {k: v for k, v in context.items() if v not in (None, "")}

        evidence = [{
            "id": ev_id,
            "source": channel if channel != "sysmon" else "sysmon",
            "eventId": event.get("event_id"),
            "time": ts_iso,
            "description": description,
            "fields": context,
        }]
        for rel in related_evidence or []:
            evidence.append(rel)
        ev_ids = [e["id"] for e in evidence]

        return {
            "attack_type": ATTACK_TYPE,
            "rule_id": rule_id,
            "title": title,
            "confidence_tier": tier,
            "confidence": confidence,
            "severity": _severity(risk),
            "risk_score": risk,
            "timestamp": ts,
            "host": self.hostname,
            "user": user,
            "pid": event.get("pid") or 0,
            "process_name": event.get("process_name") or _basename(context.get("Image")) or "unknown",
            "image": context.get("Image", ""),
            "evidence": evidence,
            "mitre": map_mitre_techniques(mitre_key, ev_ids, extra_techniques),
            "indicators": [{"type": t, "description": d, "observedAt": ts_iso} for t, d in indicators],
            "_dedup_key": dedup_key,
            "_tag": tag,        # role within an attack sequence (used for merged titles)
            "_detail": detail,
        }

    # ── PE-01: Unexpected privileged process execution ─────────────────────

    def _pe01_privileged_process(self, event):
        data = event.get("data") or {}
        integrity = (data.get("IntegrityLevel") or "").lower()
        if integrity not in ("high", "system"):
            return None
        image = data.get("Image") or event.get("image") or ""
        name = _basename(image)
        parent_name = _basename(data.get("ParentImage"))

        if _in_writable_path(image):
            risk = 85 if integrity == "system" else 75
            return self._build_alert(
                event, "PE-01", "PE-01",
                f"Privileged process from user-writable path ({name})",
                "likely", risk,
                f"{name} executed with {integrity.capitalize()} integrity from a user-writable location: {image}",
                [("PROCESS", f"{integrity.capitalize()}-integrity execution of {image}"),
                 ("PARENT_PROCESS", f"Parent: {data.get('ParentImage', '')}")],
                {},
                f"PE-01|path|{image.lower()}",
            )

        if (integrity == "system" and _is_system_user(data.get("User"))
                and name in ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe")
                and parent_name and parent_name not in SYSTEM_MANAGER_PARENTS):
            return self._build_alert(
                event, "PE-01", "PE-01",
                f"Unexpected SYSTEM {name} (parent {parent_name})",
                "suspicious", 72,
                f"{name} running as NT AUTHORITY\\SYSTEM was started by unexpected parent {data.get('ParentImage')}",
                [("PROCESS", f"SYSTEM-level {name} started by {parent_name}")],
                {},
                f"PE-01|sys|{parent_name}|{name}",
            )
        return None

    # ── PE-02: Suspicious parent-child chain with elevated execution ───────

    def _pe02_parent_child(self, event):
        data = event.get("data") or {}
        integrity = (data.get("IntegrityLevel") or "").lower()
        if integrity not in ("high", "system"):
            return None
        image = data.get("Image") or ""
        name = _basename(image)
        parent_image = data.get("ParentImage") or ""
        parent_name = _basename(parent_image)
        parent = self._proc_cache.get(data.get("ParentProcessGuid") or "", {})
        parent_integrity = parent.get("integrity", "")

        # Medium/Low -> SYSTEM is not a standard UAC transition (UAC yields High)
        if integrity == "system" and parent_integrity in ("medium", "low") \
                and parent_name not in SYSTEM_MANAGER_PARENTS:
            return self._build_alert(
                event, "PE-02", "PE-02",
                f"Integrity jump {parent_integrity.capitalize()} -> System ({parent_name} -> {name})",
                "confirmed", 92,
                f"{parent_name} ({parent_integrity} integrity, user {parent.get('user', '?')}) spawned {name} at System integrity",
                [("PROCESS_CHAIN", f"{parent_image} [{parent_integrity}] -> {image} [system]")],
                {"ParentIntegrityLevel": parent_integrity, "ParentUser": parent.get("user", "")},
                f"PE-02|jump|{parent_name}|{name}",
            )

        if name in SHELLS_AND_LOLBINS and parent_name in SERVICE_ACCOUNT_HOSTS and integrity == "system":
            return self._build_alert(
                event, "PE-02", "PE-02",
                f"Service host spawned SYSTEM shell ({parent_name} -> {name})",
                "likely", 85,
                f"Service-account process {parent_name} spawned {name} at System integrity (possible token impersonation)",
                [("PROCESS_CHAIN", f"{parent_image} -> {image} [system]")],
                {},
                f"PE-02|svc|{parent_name}|{name}",
                extra_techniques=["T1134.001"],
            )

        if name in SHELLS_AND_LOLBINS and parent_name in OFFICE_AND_SCRIPT_HOSTS:
            return self._build_alert(
                event, "PE-02", "PE-02",
                f"Elevated shell from document/script host ({parent_name} -> {name})",
                "likely", 80,
                f"{parent_name} spawned {name} with {integrity.capitalize()} integrity",
                [("PROCESS_CHAIN", f"{parent_image} -> {image} [{integrity}]")],
                {},
                f"PE-02|office|{parent_name}|{name}",
            )
        return None

    # ── PE-03: Account / privileged-group membership changes ───────────────

    def _pe03_account_cmdline(self, event):
        data = event.get("data") or {}
        cmd = (data.get("CommandLine") or "")
        low = cmd.lower()
        name = _basename(data.get("Image") or event.get("image"))
        # Strip the executable token so net.exe and its net1.exe child dedupe together
        args_key = re.sub(r"^\S*net1?(\.exe)?\"?\s*", "", low.strip())

        is_net = name in ("net.exe", "net1.exe")
        is_ps = name in ("powershell.exe", "pwsh.exe")
        group_add = (is_net and re.search(r"\b(localgroup|group)\b", low) and "/add" in low) or \
                    (is_ps and "add-localgroupmember" in low) or \
                    (is_ps and "add-adgroupmember" in low)
        if group_add:
            privileged = next((g for g in PRIVILEGED_GROUPS if g in low), None)
            if not privileged:
                return None
            risk = 90 if privileged in ("domain admins", "enterprise admins", "schema admins") else 85
            return self._build_alert(
                event, "PE-03", "PE-03-GROUP",
                f"Account added to privileged group '{privileged}'",
                "likely", risk,
                f"Privileged group membership change via command line: {cmd}",
                [("ACCOUNT_MANIPULATION", f"Membership added to '{privileged}': {cmd}")],
                {"Group": privileged},
                f"PE-03|grp|{args_key}",
                tag="group", detail=privileged,
            )

        user_add = (is_net and re.search(r"\buser\b", low) and "/add" in low) or \
                   (is_ps and ("new-localuser" in low or "new-aduser" in low))
        if user_add:
            return self._build_alert(
                event, "PE-03", "PE-03-USER",
                "Local account created via command line",
                "suspicious", 60,
                f"New account created via command line: {cmd}",
                [("ACCOUNT_CREATION", cmd)],
                {},
                f"PE-03|user|{args_key}",
                tag="user", detail=(re.search(r"\buser\s+(\S+)", low) or [None, None])[1],
            )
        return None

    def _pe03_security_log(self, event):
        data = event.get("data") or {}
        eid = event.get("event_id")
        subject = f"{data.get('SubjectDomainName', '')}\\{data.get('SubjectUserName', '')}"
        if eid == 4720:
            target = data.get("TargetUserName", "")
            return self._build_alert(
                event, "PE-03", "PE-03-USER",
                f"User account created: {target}",
                "suspicious", 60,
                f"Security 4720: account '{target}' created by {subject}",
                [("ACCOUNT_CREATION", f"Account '{target}' created by {subject}")],
                {"TargetUserName": target, "TargetSid": data.get("TargetSid", "")},
                f"PE-03|4720|{target.lower()}",
                tag="user", detail=target,
            )
        group = (data.get("TargetUserName") or "").lower()
        group_sid = (data.get("TargetSid") or "").lower()
        if group not in PRIVILEGED_GROUPS and group_sid not in PRIVILEGED_GROUP_SIDS \
                and not group_sid.endswith(("-512", "-518", "-519")):
            return None
        member = data.get("MemberName") or data.get("MemberSid") or "?"
        risk = 90 if group in ("domain admins", "enterprise admins", "schema admins") \
            or group_sid.endswith(("-512", "-518", "-519")) else 85
        return self._build_alert(
            event, "PE-03", "PE-03-GROUP",
            f"Member added to privileged group '{data.get('TargetUserName')}'",
            "confirmed", risk,
            f"Security {eid}: {member} added to '{data.get('TargetUserName')}' by {subject}",
            [("ACCOUNT_MANIPULATION", f"{member} added to privileged group '{data.get('TargetUserName')}'")],
            {"Group": data.get("TargetUserName", ""), "GroupSid": data.get("TargetSid", ""),
             "MemberName": data.get("MemberName", ""), "MemberSid": data.get("MemberSid", "")},
            f"PE-03|grp|{group}|{(data.get('MemberSid') or member).lower()}",
            tag="group", detail=data.get("TargetUserName", ""),
        )

    # ── PE-04: Elevated service / scheduled-task creation ──────────────────

    def _pe04_service_task_cmdline(self, event):
        data = event.get("data") or {}
        cmd = data.get("CommandLine") or ""
        low = cmd.lower()
        name = _basename(data.get("Image") or event.get("image"))

        is_service = (name == "sc.exe" and re.search(r"\b(create|config)\b", low) and "binpath" in low) or \
                     (name in ("powershell.exe", "pwsh.exe") and "new-service" in low)
        is_task = (name == "schtasks.exe" and "/create" in low and
                   (re.search(r"/ru\s+\"?(nt authority\\)?system", low) or "/rl highest" in low)) or \
                  (name in ("powershell.exe", "pwsh.exe") and "register-scheduledtask" in low and
                   ("highest" in low or "system" in low))
        if not (is_service or is_task):
            return None

        risky_payload = _in_writable_path(low) or any(s in low for s in ("cmd.exe /c", "cmd /c", "powershell", "-enc", "mshta", "rundll32"))
        kind = "service" if is_service else "SYSTEM/highest scheduled task"
        return self._build_alert(
            event, "PE-04", "PE-04-SERVICE" if is_service else "PE-04-TASK",
            f"Elevated {kind} created via {name}",
            "likely" if risky_payload else "suspicious", 85 if risky_payload else 65,
            f"{name} created a {kind}" + (" pointing to a user-writable path or script interpreter" if risky_payload else "") + f": {cmd}",
            [("PERSISTENCE", f"{kind} creation: {cmd}")],
            {"PayloadInUserWritablePathOrInterpreter": risky_payload},
            f"PE-04|cmd|{low.strip()}",
        )

    def _pe04_service_imagepath(self, event):
        data = event.get("data") or {}
        target = (data.get("TargetObject") or "").lower()
        if "\\currentcontrolset\\services\\" not in target or not target.endswith("\\imagepath"):
            return None
        details = data.get("Details") or ""
        if not (_in_writable_path(details) or any(s in details.lower() for s in ("cmd.exe", "powershell", "mshta", "rundll32"))):
            return None
        service = target.split("\\services\\")[1].split("\\")[0]
        return self._build_alert(
            event, "PE-04", "PE-04-SERVICE",
            f"Service ImagePath set to suspicious binary ({service})",
            "likely", 85,
            f"Service '{service}' ImagePath set to {details} by {event.get('process_name')}",
            [("REGISTRY", f"{data.get('TargetObject')} = {details}")],
            {"TargetObject": data.get("TargetObject", ""), "Details": details, "ServiceName": service},
            f"PE-04|svc|{service}",
            extra_techniques=["T1112"],
        )

    def _pe04_event_log(self, event):
        data = event.get("data") or {}
        eid = event.get("event_id")
        if eid in (7045, 4697):
            service = data.get("ServiceName", "")
            path = data.get("ImagePath") or data.get("ServiceFileName") or ""
            account = data.get("AccountName") or data.get("ServiceAccount") or ""
            lowp = path.lower()
            suspicious = _in_writable_path(lowp) or any(s in lowp for s in ("cmd.exe", "cmd /c", "powershell", "%comspec%", "admin$", "mshta", "rundll32"))
            if not suspicious:
                return None
            return self._build_alert(
                event, "PE-04", "PE-04-SERVICE",
                f"Suspicious service installed: {service}",
                "likely", 85,
                f"Event {eid}: service '{service}' installed with binary '{path}' (account: {account or 'LocalSystem'})",
                [("PERSISTENCE", f"Service '{service}' -> {path}")],
                {"ServiceName": service, "ServiceImagePath": path, "ServiceAccount": account},
                f"PE-04|svc|{service.lower()}",
            )
        # 4698: scheduled task created
        content = data.get("TaskContent") or ""
        lowc = content.lower()
        privileged = "highestavailable" in lowc or "s-1-5-18" in lowc or "<userid>system</userid>" in lowc
        cmd = " ".join(re.findall(r"<(?:Command|Arguments)>(.*?)</(?:Command|Arguments)>", content, re.S | re.I))
        risky = _in_writable_path(cmd) or any(s in cmd.lower() for s in ("cmd.exe", "powershell", "mshta", "rundll32", "-enc"))
        if not (privileged and risky):
            return None
        task = data.get("TaskName", "")
        return self._build_alert(
            event, "PE-04", "PE-04-TASK",
            f"Privileged scheduled task created: {task}",
            "likely", 82,
            f"Security 4698: task '{task}' runs '{cmd.strip()}' with SYSTEM/highest privileges",
            [("PERSISTENCE", f"Task '{task}' -> {cmd.strip()}")],
            {"TaskName": task, "TaskAction": cmd.strip()},
            f"PE-04|task|{task.lower()}",
        )

    # ── PE-05: Known privilege-escalation / UAC-bypass indicators ──────────

    def _pe05_uac_registry(self, event):
        data = event.get("data") or {}
        target = (data.get("TargetObject") or "").lower()
        hijack_key = next((k for k in UAC_HIJACK_KEYS if k in target), None)
        if not hijack_key:
            return None
        ts = event.get("timestamp") or datetime.now(timezone.utc)
        self._recent_uac_reg_writes.append({"mono": self._clock(), "target": data.get("TargetObject", ""),
                                            "details": data.get("Details", ""), "time": ts})
        self._recent_uac_reg_writes = self._recent_uac_reg_writes[-20:]
        return self._build_alert(
            event, "PE-05", "PE-05-UAC-REG",
            f"UAC bypass registry hijack key modified ({event.get('process_name')})",
            "likely", 80,
            f"Write to known UAC-bypass hijack key: {data.get('TargetObject')} = {data.get('Details', '')}",
            [("REGISTRY", f"UAC hijack key modified: {data.get('TargetObject')}")],
            {"TargetObject": data.get("TargetObject", ""), "Details": data.get("Details", ""),
             "EventType": data.get("EventType", "")},
            # One alert per hijack key: (Default) and DelegateExecute writes are one technique
            f"PE-05|reg|{hijack_key}",
            tag="uac_reg",
        )

    def _pe05_process_indicators(self, event) -> List[Optional[Dict[str, Any]]]:
        data = event.get("data") or {}
        image = data.get("Image") or event.get("image") or ""
        name = _basename(image)
        parent_name = _basename(data.get("ParentImage"))
        cmd = data.get("CommandLine") or ""
        low = f"{image} {cmd}".lower()
        out: List[Optional[Dict[str, Any]]] = []

        # Auto-elevate binary executed shortly after a hijack-key write
        if name in AUTO_ELEVATE_BINARIES:
            now = self._clock()
            recent = [w for w in self._recent_uac_reg_writes if now - w["mono"] <= UAC_HIJACK_CORRELATION_SECONDS]
            if recent:
                w = recent[-1]
                related = [{
                    "id": f"ev-pe-05-reg-ctx-{int(now * 1000)}",
                    "source": "sysmon",
                    "eventId": 13,
                    "time": w["time"].isoformat() if hasattr(w["time"], "isoformat") else str(w["time"]),
                    "description": "Preceding UAC hijack registry write",
                    "fields": {"TargetObject": w["target"], "Details": w["details"]},
                }]
                out.append(self._build_alert(
                    event, "PE-05", "PE-05-UAC-EXEC",
                    f"UAC bypass executed via {name}",
                    "confirmed", 92,
                    f"Auto-elevating binary {name} launched within {UAC_HIJACK_CORRELATION_SECONDS}s of UAC hijack key write ({w['target']})",
                    [("PROCESS", f"Auto-elevate binary {image} launched after registry hijack"),
                     ("REGISTRY", f"Hijack key: {w['target']} = {w['details']}")],
                    {},
                    f"PE-05|exec|{name}",
                    tag="uac_exec", detail=name,
                    related_evidence=related,
                ))

        # Auto-elevate binary spawning a shell / user-writable payload
        if parent_name in AUTO_ELEVATE_BINARIES and (name in SHELLS_AND_LOLBINS or _in_writable_path(image)):
            out.append(self._build_alert(
                event, "PE-05", "PE-05-UAC-EXEC",
                f"Auto-elevate binary spawned {name} ({parent_name} -> {name})",
                "confirmed", 90,
                f"{parent_name} (auto-elevating) spawned {image} with {data.get('IntegrityLevel', '?')} integrity — UAC bypass pattern",
                [("PROCESS_CHAIN", f"{data.get('ParentImage', '')} -> {image}")],
                {},
                f"PE-05|child|{parent_name}|{name}",
                tag="uac_child", detail=parent_name,
            ))

        # Known privilege escalation tooling
        for pattern, label, extra in KNOWN_PE_TOOLS:
            if pattern in low:
                out.append(self._build_alert(
                    event, "PE-05", "PE-05-TOOL",
                    f"Known privilege escalation tool: {label}",
                    "likely", 88,
                    f"Process command line/image matches known privilege escalation tool '{label}': {cmd or image}",
                    [("TOOL_SIGNATURE", f"{label} indicator in {name}")],
                    {"MatchedIndicator": pattern},
                    f"PE-05|tool|{pattern}|{image.lower()}",
                    extra_techniques=extra,
                ))
                break

        # PsExec -s (spawn as SYSTEM)
        if re.search(r"psexec(64)?(\.exe)?\b", low) and re.search(r"\s[-/]s\b", cmd.lower()):
            out.append(self._build_alert(
                event, "PE-05", "PE-05-TOOL",
                "PsExec launched with -s (run as SYSTEM)",
                "suspicious", 70,
                f"PsExec invoked to run a process as SYSTEM: {cmd}",
                [("TOOL_SIGNATURE", f"PsExec -s: {cmd}")],
                {"MatchedIndicator": "psexec -s"},
                f"PE-05|psexec|{cmd.lower()}",
            ))
        return out

    # ── PE-06: Suspicious security-related registry changes ────────────────

    def _pe06_security_registry(self, event):
        data = event.get("data") or {}
        target_raw = data.get("TargetObject") or ""
        target = target_raw.lower()
        details = data.get("Details")
        fields = {"TargetObject": target_raw, "Details": details or "", "EventType": data.get("EventType", "")}

        if "\\image file execution options\\" in target and target.endswith("\\debugger"):
            accessibility = any(f"\\{b}\\" in target for b in ACCESSIBILITY_BINARIES)
            return self._build_alert(
                event, "PE-06", "PE-06",
                "IFEO Debugger hijack" + (" of accessibility binary" if accessibility else ""),
                "confirmed" if accessibility else "likely", 95 if accessibility else 82,
                f"Image File Execution Options debugger set: {target_raw} = {details or ''}",
                [("REGISTRY", f"IFEO Debugger: {target_raw} = {details or ''}")],
                fields,
                f"PE-06|ifeo|{target}",
                extra_techniques=["T1546.012"] + (["T1546.008"] if accessibility else []),
            )

        for needle, predicate, title, risk, tier, extra in SECURITY_REGISTRY_RULES:
            if needle in target and predicate(details):
                return self._build_alert(
                    event, "PE-06", "PE-06",
                    title,
                    tier, risk,
                    f"{title}: {target_raw} = {details or ''} (by {event.get('process_name')})",
                    [("REGISTRY", f"{target_raw} = {details or ''}")],
                    fields,
                    f"PE-06|{needle}|{target}",
                    extra_techniques=extra,
                )
        return None
