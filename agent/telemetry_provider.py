import random
import string
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class TelemetryProvider:
    """Abstract base class for telemetry collection."""

    def read_latest(self, max_events: int = 100) -> List[Dict[str, Any]]:
        raise NotImplementedError("read_latest must be implemented by subclasses")


class WindowsTelemetryProvider(TelemetryProvider):
    """Real telemetry provider reading actual Sysmon event logs from Windows."""

    def __init__(self):
        from sysmon_reader import SysmonReader
        self.reader = SysmonReader()

    def read_latest(self, max_events: int = 100) -> List[Dict[str, Any]]:
        return self.reader.read_latest(max_events)


class SimulatedTelemetryProvider(TelemetryProvider):
    """
    Simulated telemetry provider generating isolated synthetic event logs in memory.
    Supports scenarios:
    - 'normal': benign baseline
    - 'ransomware': mass file encryption telemetry
    - 'privilege_escalation' or 'privesc': UAC bypass, integrity elevation, account manipulation
    """

    RANSOM_EXTENSIONS = [".locked", ".encrypted", ".crypt", ".wncry", ".ryk"]
    BENIGN_EXTENSIONS = [".txt", ".docx", ".xlsx", ".json", ".log", ".tmp"]

    def __init__(self, scenario: str = "normal", instance_id: Optional[str] = None, clock=time.monotonic):
        self.scenario = scenario.lower()
        self._clock = clock
        self._privesc_started_at: Optional[float] = None
        self._privesc_emitted: set = set()
        self.privesc_complete = False
        self.instance_id = instance_id or f"sim_{random.randint(1000, 9999)}"

        pid_offset = random.randint(100, 900) * 10
        self._record_id = random.randint(10000, 50000)
        self._benign_pids = [1100 + pid_offset, 2200 + pid_offset, 3300 + pid_offset]
        self._ransom_pid = 9000 + pid_offset
        self._privesc_pid = 7500 + pid_offset
        self._step = 0

    def set_scenario(self, scenario: str):
        self.scenario = scenario.lower()
        self._privesc_started_at = None
        self._privesc_emitted = set()
        self.privesc_complete = False

    def _random_entropy_name(self, length: int = 12) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    # ── Privilege escalation timeline ─────────────────────────────────────────
    # (offset seconds, step id, description). Spans ~18s of agent run time so
    # events arrive across several 3s polls instead of all at once.
    # Three stages -> three detections once the detector groups each stage's
    # events: PE-05 (UAC bypass), PE-03 (privileged group change), PE-04 (SYSTEM task).
    PRIVESC_TIMELINE = (
        (0.0,  "recon",          "Recon: whoami /priv and admin group enumeration (benign)"),
        (3.0,  "uac_reg",        "Stage 1/3: UAC bypass registry hijack (ms-settings)"),
        (6.0,  "uac_exec",       "Stage 1/3: auto-elevating fodhelper.exe -> elevated cmd.exe"),
        (9.0,  "account_create", "Stage 2/3: backdoor account backup_admin created"),
        (12.0, "account_group",  "Stage 2/3: backup_admin added to Administrators"),
        (15.0, "task",           "Stage 3/3: SYSTEM scheduled task pointing to user-writable payload"),
    )
    PRIVESC_DURATION_SECONDS = 18.0

    def _sysmon_proc(self, now, pid, image, cmd, parent_pid, parent_image, integrity, user, guid, parent_guid):
        """Builds a Sysmon Event 1 (ProcessCreate) shaped like SysmonReader output."""
        self._record_id += 1
        return {
            "record_id": self._record_id,
            "timestamp": now,
            "event_id": 1,
            "pid": pid,
            "process_name": image.split("\\")[-1],
            "image": image,
            "data": {
                "UtcTime": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "ProcessGuid": guid,
                "ProcessId": str(pid),
                "Image": image,
                "CommandLine": cmd,
                "CurrentDirectory": "C:\\Users\\StandardUser\\",
                "User": user,
                "IntegrityLevel": integrity,
                "ParentProcessGuid": parent_guid,
                "ParentProcessId": str(parent_pid),
                "ParentImage": parent_image,
                "ParentCommandLine": parent_image,
            },
        }

    def _sysmon_reg(self, now, pid, image, target, details, user):
        """Builds a Sysmon Event 13 (RegistryValueSet) shaped like SysmonReader output."""
        self._record_id += 1
        return {
            "record_id": self._record_id,
            "timestamp": now,
            "event_id": 13,
            "pid": pid,
            "process_name": image.split("\\")[-1],
            "image": image,
            "data": {
                "EventType": "SetValue",
                "UtcTime": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "ProcessId": str(pid),
                "Image": image,
                "TargetObject": target,
                "Details": details,
                "User": user,
            },
        }

    def _privesc_step_events(self, step: str, now) -> List[Dict[str, Any]]:
        base = self._privesc_pid
        user = "WORKSTATION\\StandardUser"
        sys32 = "C:\\Windows\\System32\\"
        ps = sys32 + "WindowsPowerShell\\v1.0\\powershell.exe"
        cmd = sys32 + "cmd.exe"
        payload = "C:\\Users\\Public\\updater.exe"

        def g(n):
            return "{%08d-5e1f-6a2b-0000-00000000%04d}" % (base, n)

        P = self._sysmon_proc
        R = self._sysmon_reg

        if step == "recon":
            return [
                P(now, base, ps, "powershell.exe -nop", 4100, "C:\\Windows\\explorer.exe", "Medium", user, g(1), g(0)),
                P(now, base + 1, sys32 + "whoami.exe", "whoami /priv", base, ps, "Medium", user, g(2), g(1)),
                P(now, base + 2, sys32 + "net.exe", "net localgroup administrators", base, ps, "Medium", user, g(3), g(1)),
            ]
        if step == "uac_reg":
            key = ("HKU\\S-1-5-21-1004336348-1177238915-682003330-1001"
                   "\\Software\\Classes\\ms-settings\\shell\\open\\command")
            return [
                R(now, base, ps, key + "\\(Default)", cmd, user),
                R(now, base, ps, key + "\\DelegateExecute", "(Empty)", user),
            ]
        if step == "uac_exec":
            fod = sys32 + "fodhelper.exe"
            return [
                P(now, base + 10, fod, '"%s"' % fod, base, ps, "High", user, g(10), g(1)),
                P(now, base + 11, cmd, '"%s"' % cmd, base + 10, fod, "High", user, g(11), g(10)),
            ]
        if step == "account_create":
            return [
                P(now, base + 20, sys32 + "net.exe", "net user backup_admin S3cure!Pass /add",
                  base + 11, cmd, "High", user, g(20), g(11)),
            ]
        if step == "account_group":
            return [
                P(now, base + 21, sys32 + "net.exe", "net localgroup administrators backup_admin /add",
                  base + 11, cmd, "High", user, g(21), g(11)),
                P(now, base + 22, sys32 + "net1.exe",
                  "C:\\Windows\\system32\\net1 localgroup administrators backup_admin /add",
                  base + 21, sys32 + "net.exe", "High", user, g(22), g(21)),
            ]
        if step == "task":
            return [
                P(now, base + 30, sys32 + "schtasks.exe",
                  'schtasks /create /tn "OneDriveUpdate" /tr "%s" /sc onlogon /ru SYSTEM /f' % payload,
                  base + 11, cmd, "High", user, g(30), g(11)),
            ]
        return []

    def _privesc_timeline_events(self, now) -> List[Dict[str, Any]]:
        """Emits each attack step once, when its offset is reached; benign-only afterwards."""
        if self.privesc_complete:
            return []
        if self._privesc_started_at is None:
            self._privesc_started_at = self._clock()
            print(f"[Simulator] Privilege escalation simulation started "
                  f"(~{self.PRIVESC_DURATION_SECONDS:.0f}s attack timeline)")
        elapsed = self._clock() - self._privesc_started_at
        out: List[Dict[str, Any]] = []
        for offset, step, label in self.PRIVESC_TIMELINE:
            if offset <= elapsed and step not in self._privesc_emitted:
                self._privesc_emitted.add(step)
                print(f"[Simulator] t+{elapsed:4.1f}s  {label}")
                out.extend(self._privesc_step_events(step, now))
        if elapsed >= self.PRIVESC_DURATION_SECONDS and len(self._privesc_emitted) == len(self.PRIVESC_TIMELINE):
            self.privesc_complete = True
            print("[Simulator] Privilege escalation simulation complete; emitting benign telemetry only")
        return out

    def read_latest(self, max_events: int = 100) -> List[Dict[str, Any]]:
        self._step += 1
        events: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        # ── 1. Simulate background benign endpoint activity ───────────────────
        self._record_id += 1
        base_pid = self._benign_pids[0]
        ext = random.choice(self.BENIGN_EXTENSIONS)
        events.append({
            "record_id": self._record_id,
            "timestamp": now,
            "event_id": 11,
            "pid": base_pid,
            "process_name": "explorer.exe",
            "image": "C:\\Program Files\\SimulatedApp\\explorer.exe",
            "data": {
                "TargetFilename": f"C:\\Users\\StandardUser\\Documents\\notes_{self._record_id}{ext}",
            }
        })

        for pid in self._benign_pids:
            proc_name = "explorer.exe" if pid == self._benign_pids[0] else (
                "chrome.exe" if pid == self._benign_pids[1] else "code.exe"
            )
            img_path = f"C:\\Program Files\\SimulatedApp\\{proc_name}"

            if random.random() < 0.40:
                self._record_id += 1
                ext = random.choice(self.BENIGN_EXTENSIONS)
                events.append({
                    "record_id": self._record_id,
                    "timestamp": now,
                    "event_id": 11,
                    "pid": pid,
                    "process_name": proc_name,
                    "image": img_path,
                    "data": {
                        "TargetFilename": f"C:\\Users\\StandardUser\\Documents\\document_{self._record_id}{ext}",
                    }
                })

            if random.random() < 0.30:
                self._record_id += 1
                events.append({
                    "record_id": self._record_id,
                    "timestamp": now,
                    "event_id": 3,
                    "pid": pid,
                    "process_name": proc_name,
                    "image": img_path,
                    "data": {
                        "DestinationIp": f"10.0.0.{random.randint(2, 250)}",
                        "DestinationHostname": "internal-service.local",
                    }
                })

            if random.random() < 0.25:
                self._record_id += 1
                events.append({
                    "record_id": self._record_id,
                    "timestamp": now,
                    "event_id": 22,
                    "pid": pid,
                    "process_name": proc_name,
                    "image": img_path,
                    "data": {
                        "QueryName": "api.sentineliq-simulated.io",
                    }
                })

        # ── 2. Simulate ransomware burst when scenario is active ───────────────
        if self.scenario == "ransomware":
            subdirs = ["Documents", "Desktop", "AppData\\Local\\Temp", "Downloads"]
            for _ in range(25):
                self._record_id += 1
                ext = random.choice(self.RANSOM_EXTENSIONS)
                rand_entropy = self._random_entropy_name(14)
                target_dir = random.choice(subdirs)
                filepath = f"C:\\Users\\StandardUser\\{target_dir}\\financial_{self._record_id}_{rand_entropy}{ext}"

                events.append({
                    "record_id": self._record_id,
                    "timestamp": now,
                    "event_id": 11,
                    "pid": self._ransom_pid,
                    "process_name": "ransomware_demo.exe",
                    "image": "C:\\Users\\StandardUser\\AppData\\Local\\Temp\\ransomware_demo.exe",
                    "data": {
                        "TargetFilename": filepath,
                    }
                })

                if random.random() < 0.5:
                    self._record_id += 1
                    events.append({
                        "record_id": self._record_id,
                        "timestamp": now,
                        "event_id": 2,
                        "pid": self._ransom_pid,
                        "process_name": "ransomware_demo.exe",
                        "image": "C:\\Users\\StandardUser\\AppData\\Local\\Temp\\ransomware_demo.exe",
                        "data": {
                            "TargetFilename": filepath,
                        }
                    })

        # ── 3. Simulate a timed privilege escalation attack chain ─────────────
        if self.scenario in ("privilege_escalation", "privesc"):
            events.extend(self._privesc_timeline_events(now))

        return events
