"""
Live monitor pipeline tests WITHOUT Npcap/scapy: a synthetic in-memory CaptureSource feeds real
frames through the real rolling-window extraction and the real trained model, and we assert the
genuine behaviour (a flood raises exactly one LIVE alert; benign traffic raises none; shutdown is
clean). Only the actual NIC binding (scapy) is not exercised here.

Needs numpy/xgboost -> run with the ml-service venv:
  ../apps/ml-service/.venv/Scripts/python.exe -m unittest tests.test_live
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import generate_dos_pcap as gen  # noqa: E402
from netsensor import live  # noqa: E402
from netsensor.pcap_reader import read_capture  # noqa: E402
from netsensor.stats import Stats  # noqa: E402
from netsensor.schema import KEY_COLUMNS, FEATURE_NAMES  # noqa: E402

BUNDLE = r"C:\datasets\dos-models\dos-xgb-d0311-v1"


def _frames_from_pcap(path):
    with open(path, "rb") as stream:
        for raw in read_capture(stream, Stats()):
            yield live.RawFrame(ts_ns=raw.ts_ns, linktype=raw.linktype, data=raw.data)


class ReplayCaptureSource(live.CaptureSource):
    """Feeds pre-recorded frames, then a few idle ticks so trailing windows flush, then ends."""
    def __init__(self, frames, name="test0"):
        self._frames = list(frames)
        self._name = name
        self.closed = False
        self.dropped = 0

    def frames(self):
        for f in self._frames:
            yield f
        for _ in range(3):
            yield None

    def close(self):
        self.closed = True

    def describe(self):
        return self._name


def _args(out, **over):
    ns = type("A", (), {})()
    d = dict(out=out, target_ip="127.0.0.1", target_port=80, attacker_ip="127.0.0.1",
             benign_peer_ip="127.0.0.1", flood_seconds=20, flood_pps=1500, benign_seconds=10, benign_pps=40, now=False)
    for k, v in {**d, **over}.items():
        setattr(ns, k, v)
    return ns


class LiveStructureTest(unittest.TestCase):
    def test_window_row_schema_matches_model_input(self):
        # The live monitor scores rows with exactly the dos-window-v1 key+feature columns.
        self.assertEqual(live.WINDOW_ROW_COLUMNS, KEY_COLUMNS + FEATURE_NAMES)

    def test_missing_scapy_gives_setup_instructions(self):
        # When scapy is absent, the user gets install instructions, not a stack trace.
        try:
            import scapy.all  # noqa
            have_scapy = True
        except Exception:
            have_scapy = False
        if have_scapy:
            self.skipTest("scapy present; the no-scapy path is not exercised")
        with self.assertRaises(SystemExit) as cm:
            live.list_interfaces()
        self.assertIn("scapy", str(cm.exception))

    def test_capture_fails_fast_without_npcap_provider(self):
        # Listing interfaces can work without Npcap, but CAPTURE must fail fast (not silently see
        # zero packets). This is the exact "listing != capture" trap.
        try:
            import scapy.all  # noqa
        except Exception:
            self.skipTest("scapy not installed")
        if live.capture_provider_available():
            self.skipTest("a capture provider (Npcap) IS present; the guard is not exercised here")
        for call in (lambda: live.ScapyCaptureSource("\\Device\\NPF_test"),
                     lambda: live.capture_smoke_test("\\Device\\NPF_test", seconds=1)):
            with self.assertRaises(SystemExit) as cm:
                call()
            self.assertIn("Npcap", str(cm.exception))


@unittest.skipUnless(os.path.isdir(BUNDLE), f"trained bundle not present at {BUNDLE}")
class LiveDetectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from netsensor.ml.model import DosDetector
        cls.detector = DosDetector.load(BUNDLE)
        cls.tmp = tempfile.mkdtemp()

    def _monitor(self, frames):
        forwarded = []
        mon = live.LiveMonitor(self.detector, "o" * 24, "e" * 24, forward_fn=forwarded.append,
                               limits=live.MonitorLimits(warmup_seconds=0.0))
        src = ReplayCaptureSource(frames)
        status = mon.run(src)
        return forwarded, status, src

    def test_flood_raises_exactly_one_live_alert(self):
        pcap = os.path.join(self.tmp, "flood.pcap")
        gen.generate(_args(pcap))
        forwarded, status, src = self._monitor(_frames_from_pcap(pcap))
        self.assertEqual(len(forwarded), 1, "a sustained flood raises exactly one alert episode")
        alert = forwarded[0]
        self.assertEqual(alert["attackType"], "DOS_DDOS")
        self.assertEqual(alert["dataOrigin"], "LIVE", "live capture is labelled LIVE, never PCAP_REPLAY")
        self.assertEqual(alert["detectorStatus"], "TRAINED")
        self.assertTrue(any(e["id"] == "dos-window" for e in alert["evidence"]))
        self.assertFalse(any(e["id"] == "pcap-provenance" for e in alert["evidence"]), "live alerts carry no capture-file provenance")
        self.assertTrue(src.closed, "the capture handle is closed on shutdown")
        self.assertFalse(status.running)
        self.assertGreaterEqual(status.alerts, 1)

    def test_benign_traffic_does_not_alert(self):
        pcap = os.path.join(self.tmp, "benign.pcap")
        # No flood segment: only low-rate, few-source-port benign traffic.
        gen.generate(_args(pcap, flood_seconds=0, benign_seconds=20, benign_pps=50))
        forwarded, status, _ = self._monitor(_frames_from_pcap(pcap))
        self.assertEqual(len(forwarded), 0, "benign traffic must never become an attack alert")
        self.assertEqual(status.alerts, 0)
        self.assertGreater(status.windows_scored, 0, "windows were still scored (negative result, not no-op)")

    def test_forward_failure_does_not_crash_monitoring(self):
        pcap = os.path.join(self.tmp, "flood2.pcap")
        gen.generate(_args(pcap))

        def boom(_payload):
            raise RuntimeError("backend down")

        mon = live.LiveMonitor(self.detector, "o" * 24, "e" * 24, forward_fn=boom,
                               limits=live.MonitorLimits(warmup_seconds=0.0))
        status = mon.run(ReplayCaptureSource(_frames_from_pcap(pcap)))
        self.assertFalse(status.running)
        self.assertIsNotNone(status.error)
        self.assertIn("forward failed", status.error)

    def test_stop_ends_the_run(self):
        pcap = os.path.join(self.tmp, "flood3.pcap")
        gen.generate(_args(pcap, flood_seconds=5, flood_pps=500, benign_seconds=1, benign_pps=10))
        forwarded = []
        mon = live.LiveMonitor(self.detector, "o" * 24, "e" * 24, forward_fn=forwarded.append,
                               limits=live.MonitorLimits(warmup_seconds=0.0))
        mon.stop()  # stop before running: the loop exits immediately after the first frame check
        src = ReplayCaptureSource(_frames_from_pcap(pcap))
        status = mon.run(src)
        self.assertTrue(src.closed)
        self.assertFalse(status.running)


if __name__ == "__main__":
    unittest.main()
