"""Smoke tests for the PE-01..PE-06 privilege escalation rules and alert grouping (no real elevation)."""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from privilege_escalation import PrivilegeEscalationDetector


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def proc(image, parent, integrity="Medium", cmd="", user="HOST\\alice", guid=None, parent_guid=None):
    return {"record_id": 1, "timestamp": datetime.now(timezone.utc), "event_id": 1, "pid": 100,
            "process_name": image.split("\\")[-1], "image": image,
            "data": {"Image": image, "ParentImage": parent, "IntegrityLevel": integrity, "CommandLine": cmd,
                     "User": user, "ProcessGuid": guid or "", "ParentProcessGuid": parent_guid or ""}}


def reg(target, details="", image="C:\\Windows\\System32\\reg.exe"):
    return {"record_id": 2, "timestamp": datetime.now(timezone.utc), "event_id": 13, "pid": 200,
            "process_name": image.split("\\")[-1], "image": image,
            "data": {"TargetObject": target, "Details": details, "Image": image}}


def sec(event_id, **data):
    return {"record_id": 5, "timestamp": datetime.now(timezone.utc), "event_id": event_id, "pid": None,
            "process_name": None, "image": None, "channel": "security",
            "data": {"SubjectUserName": "alice", "SubjectDomainName": "HOST", **data}}


UAC_KEY = "HKU\\S-1-5-21\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)"
NET_ADMIN_ADD = "net localgroup administrators eve /add"


class TestPERules(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.d = PrivilegeEscalationDetector(hostname="TEST-HOST", clock=self.clock)

    def alerts(self, *events):
        return self.d.process_events(list(events)) + self.d.flush_all()

    def rules(self, *events):
        return [a["rule_id"] for a in self.alerts(*events)]

    def test_pe01_privileged_binary_in_temp(self):
        self.assertIn("PE-01", self.rules(proc("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe", "C:\\x\\explorer.exe", "High")))

    def test_pe02_medium_to_system(self):
        parent = proc("C:\\Tools\\loader.exe", "C:\\Windows\\explorer.exe", "Medium", guid="{P}")
        child = proc("C:\\Windows\\System32\\notepad.exe", "C:\\Tools\\loader.exe", "System",
                     user="NT AUTHORITY\\SYSTEM", parent_guid="{P}")
        self.assertIn("PE-02", self.rules(parent, child))

    def test_pe03_admin_group_add(self):
        a = self.alerts(proc("C:\\Windows\\System32\\net.exe", "C:\\Windows\\System32\\cmd.exe", "High", NET_ADMIN_ADD))
        self.assertEqual([x["rule_id"] for x in a], ["PE-03"])
        self.assertIn("T1098", [m["techniqueId"] for m in a[0]["mitre"]])

    def test_pe04_system_task(self):
        self.assertEqual(self.rules(proc("C:\\Windows\\System32\\schtasks.exe", "C:\\Windows\\System32\\cmd.exe",
                                         "High", "schtasks /create /tn x /tr C:\\Users\\Public\\p.exe /ru SYSTEM")), ["PE-04"])

    def test_pe06_ifeo_sethc(self):
        a = self.alerts(reg("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger", "cmd.exe"))
        self.assertEqual((a[0]["rule_id"], a[0]["confidence_tier"]), ("PE-06", "confirmed"))

    def test_benign_produces_nothing(self):
        self.assertEqual(self.rules(proc("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\explorer.exe")), [])

    # ── Grouping / de-duplication ─────────────────────────────────────────

    def test_uac_sequence_merges_into_one_confirmed_alert(self):
        a = self.alerts(
            reg(UAC_KEY, "C:\\Users\\Public\\p.exe"),
            proc("C:\\Windows\\System32\\fodhelper.exe", "C:\\Windows\\System32\\cmd.exe", "High"),
            proc("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\fodhelper.exe", "High"),
        )
        self.assertEqual(len(a), 1)
        self.assertEqual((a[0]["rule_id"], a[0]["confidence_tier"], a[0]["risk_score"]), ("PE-05", "confirmed", 92))
        self.assertEqual(a[0]["correlated_events"], 3)
        self.assertIn("UAC bypass via fodhelper.exe", a[0]["title"])
        self.assertEqual({m["techniqueId"] for m in a[0]["mitre"]}, {"T1548.002", "T1112"})
        self.assertEqual(len(a[0]["evidence"]), 4)  # 3 events + preceding-registry context
        self.assertFalse(any(k.startswith("_") for k in a[0]))

    def test_alert_held_until_window_closes_then_released(self):
        e = proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High", NET_ADMIN_ADD)
        self.assertEqual(self.d.process_events([e]), [])
        self.clock.t += 9
        self.assertEqual([x["rule_id"] for x in self.d.process_events([])], ["PE-03"])

    def test_events_across_polls_within_window_merge(self):
        self.d.process_events([proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High", "net user bob P@ss /add")])
        self.clock.t += 3
        self.d.process_events([proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High",
                                    "net localgroup administrators bob /add")])
        self.clock.t += 6
        a = self.d.process_events([])
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["title"], "Account 'bob' created and added to privileged group 'administrators'")

    def test_repeat_and_lower_risk_events_suppressed_during_cooldown(self):
        e = proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High", NET_ADMIN_ADD)
        self.assertEqual(len(self.alerts(e)), 1)
        self.clock.t += 20
        self.assertEqual(self.alerts(e), [])  # identical event
        self.assertEqual(self.alerts(proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High",
                                          "net user carol P@ss /add")), [])  # lower-risk PE-03
        self.assertEqual(self.d.suppressed_count, 1)

    def test_higher_risk_or_post_cooldown_events_still_alert(self):
        self.alerts(proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High", "net user carol P@ss /add"))
        self.clock.t += 10
        self.assertEqual(self.rules(proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High", NET_ADMIN_ADD)), ["PE-03"])
        self.clock.t += 61
        self.assertEqual(self.rules(proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High",
                                         "net user dave P@ss /add")), ["PE-03"])

    def test_different_rules_stay_separate(self):
        a = self.alerts(
            proc("C:\\Windows\\System32\\net.exe", "C:\\x\\cmd.exe", "High", NET_ADMIN_ADD),
            proc("C:\\Windows\\System32\\schtasks.exe", "C:\\x\\cmd.exe", "High",
                 "schtasks /create /tn x /tr C:\\Users\\Public\\p.exe /ru SYSTEM"),
        )
        self.assertEqual(sorted(x["rule_id"] for x in a), ["PE-03", "PE-04"])

    def test_security_log_account_events_merge(self):
        a = self.alerts(
            sec(4720, TargetUserName="eve", TargetSid="S-1-5-21-1-1001"),
            sec(4732, TargetUserName="Administrators", TargetSid="S-1-5-32-544", MemberSid="S-1-5-21-1-1001"),
        )
        self.assertEqual(len(a), 1)
        self.assertEqual((a[0]["rule_id"], a[0]["confidence_tier"]), ("PE-03", "confirmed"))
        self.assertEqual(a[0]["title"], "Account 'eve' created and added to privileged group 'Administrators'")


if __name__ == "__main__":
    unittest.main()
