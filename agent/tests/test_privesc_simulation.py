"""Focused tests: timed privilege escalation simulation -> grouped detector alerts -> backend payload."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent as agent_mod
import config as cfg
from privilege_escalation import PrivilegeEscalationDetector
from sliding_window_buffer import SlidingWindowBuffer
from telemetry_provider import SimulatedTelemetryProvider


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make_agent(clock, reader_cls=SimulatedTelemetryProvider):
    """Agent with only the state _poll/_report_pe_alert need (no activation, model, or network)."""
    ag = agent_mod.Agent.__new__(agent_mod.Agent)
    ag.reader = reader_cls(scenario="privilege_escalation", clock=clock)
    ag.buffer = SlidingWindowBuffer(window_size_seconds=agent_mod.WINDOW_SIZE_SECONDS)
    ag.pe_detector = PrivilegeEscalationDetector(hostname="WS-TEST", clock=clock)
    ag._last_record_id = 0
    ag._pe_pending_events = []
    ag.isolation_provider = mock.Mock(is_isolated=False)
    return ag


def run_agent(ag, clock, seconds, step=3, flush_on_exit=True):
    """Mirrors Agent.run: poll every `step` seconds, then flush held alerts on exit."""
    seen, alerts = [], []
    for _ in range(0, seconds, step):
        ag._poll()
        seen.extend(ag._pe_pending_events)
        alerts.extend(ag.pe_detector.process_events(ag._pe_pending_events))
        clock.t += step
    if flush_on_exit:
        alerts.extend(ag.pe_detector.flush_all())
    return seen, alerts


EXPECTED = {
    ("PE-05", "confirmed", 92, "UAC bypass via fodhelper.exe: registry hijack followed by auto-elevated execution"),
    ("PE-03", "likely", 85, "Account 'backup_admin' created and added to privileged group 'administrators'"),
    ("PE-04", "likely", 85, "Elevated SYSTEM/highest scheduled task created via schtasks.exe"),
}


def summary(alerts):
    return {(a["rule_id"], a["confidence_tier"], a["risk_score"], a["title"]) for a in alerts}


class TestPrivescSimulation(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_timeline_spans_15_to_20_seconds(self):
        self.assertTrue(15 <= SimulatedTelemetryProvider.PRIVESC_DURATION_SECONDS <= 20)
        sim = SimulatedTelemetryProvider(scenario="privilege_escalation", clock=self.clock)
        polls_with_attack = 0
        for _ in range(9):
            if any(e["pid"] >= sim._privesc_pid for e in sim.read_latest()):
                polls_with_attack += 1
            self.clock.t += 3
        self.assertGreaterEqual(polls_with_attack, 5)
        self.assertTrue(sim.privesc_complete)

    def test_one_agent_run_produces_exactly_three_alerts(self):
        # 30s run as with --duration 30: every alert is released before exit
        seen, alerts = run_agent(make_agent(self.clock), self.clock, 30, flush_on_exit=False)
        self.assertEqual(len(alerts), 3)
        self.assertEqual(summary(alerts), EXPECTED)
        # All three original steps reached the detector, oldest first, no duplicates
        self.assertTrue(any(e["event_id"] == 13 and "ms-settings" in e["data"]["TargetObject"] for e in seen))
        self.assertTrue(any(e["process_name"] == "fodhelper.exe" for e in seen))
        self.assertTrue(any("localgroup administrators backup_admin /add" in e["data"].get("CommandLine", "") for e in seen))
        ids = [e["record_id"] for e in seen]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), len(set(ids)))

    def test_grouping_details(self):
        _, alerts = run_agent(make_agent(self.clock), self.clock, 30)
        by_rule = {a["rule_id"]: a for a in alerts}
        self.assertEqual(by_rule["PE-05"]["correlated_events"], 3)   # reg write + fodhelper + elevated cmd
        self.assertEqual(by_rule["PE-03"]["correlated_events"], 2)   # net user + net localgroup (net1 deduped)
        self.assertEqual(by_rule["PE-04"]["correlated_events"], 1)
        for a in alerts:
            self.assertEqual(a["attack_type"], "PRIVILEGE_ESCALATION")
            self.assertTrue(a["mitre"] and a["evidence"])

    def test_short_run_flushes_held_alerts_on_exit(self):
        _, alerts = run_agent(make_agent(self.clock), self.clock, 18)  # stops while PE-04 is still held
        self.assertEqual(summary(alerts), EXPECTED)

    def test_no_further_alerts_on_repeated_polls(self):
        ag = make_agent(self.clock)
        _, first = run_agent(ag, self.clock, 30, flush_on_exit=False)
        _, more = run_agent(ag, self.clock, 120)
        self.assertEqual(len(first), 3)
        self.assertEqual(more, [])

    def test_newest_first_source_like_real_sysmon(self):
        class NewestFirst(SimulatedTelemetryProvider):
            def read_latest(self, max_events=100):
                return list(reversed(super().read_latest(max_events)))

        _, alerts = run_agent(make_agent(self.clock, NewestFirst), self.clock, 30)
        self.assertEqual(summary(alerts), EXPECTED)

    def test_two_agents_produce_six_alerts_three_per_endpoint(self):
        posted = []
        resp = mock.Mock(status_code=201)
        resp.raise_for_status.return_value = None
        for endpoint in ("a" * 24, "b" * 24):
            clock = FakeClock()
            ag = make_agent(clock)
            _, alerts = run_agent(ag, clock, 30)
            with mock.patch.object(cfg, "ENDPOINT_ID", endpoint), \
                 mock.patch.object(cfg, "ORGANIZATION_ID", "o" * 24), \
                 mock.patch.object(cfg, "AUTO_REPORT_DETECTIONS", True), \
                 mock.patch("requests.post", side_effect=lambda url, json, headers, timeout: posted.append(json) or resp):
                for a in alerts:
                    self.assertTrue(ag._report_pe_alert(a))
            ag.isolation_provider.isolate.assert_not_called()

        self.assertEqual(len(posted), 6)
        for endpoint in ("a" * 24, "b" * 24):
            self.assertEqual(sorted(p["ruleId"] for p in posted if p["endpointId"] == endpoint), ["PE-03", "PE-04", "PE-05"])
        for body in posted:
            self.assertEqual(body["attackType"], "PRIVILEGE_ESCALATION")
            self.assertEqual(body["dataOrigin"], "SIMULATED")   # simulated telemetry is never reported as live
            self.assertIn(body["confidenceTier"], ("likely", "confirmed"))
            self.assertTrue(body["mitre"] and body["evidence"] and body["indicators"] and body["detectedAt"])


if __name__ == "__main__":
    unittest.main()
