"""
Tests for the synthetic DoS PCAP generator: it is local-only, bounded, writes a real PCAP the
sensor can read, and produces a flood with many distinct source ports plus a benign segment.
Standard library only.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import generate_dos_pcap as g  # noqa: E402
from netsensor.pcap_reader import read_capture  # noqa: E402
from netsensor.packet import decode, Packet  # noqa: E402
from netsensor.stats import Stats  # noqa: E402


def _args(**over):
    ns = type("A", (), {})()
    defaults = dict(out="", target_ip="127.0.0.1", target_port=80, attacker_ip="127.0.0.1",
                    benign_peer_ip="127.0.0.1", flood_seconds=6, flood_pps=2000,
                    benign_seconds=3, benign_pps=50, now=False)
    for k, v in {**defaults, **over}.items():
        setattr(ns, k, v)
    return ns


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "dos.pcap")

    def test_refuses_non_local_targets(self):
        for field in ("target_ip", "attacker_ip", "benign_peer_ip"):
            with self.assertRaisesRegex(SystemExit, "not loopback or a documentation range"):
                g.generate(_args(out=self.out, **{field: "8.8.8.8"}))
        self.assertFalse(os.path.exists(self.out), "nothing is written when a target is rejected")

    def test_enforces_hard_caps(self):
        with self.assertRaisesRegex(SystemExit, "pps exceeds"):
            g.generate(_args(out=self.out, flood_pps=g.MAX_PPS + 1))
        with self.assertRaisesRegex(SystemExit, "duration exceeds"):
            g.generate(_args(out=self.out, flood_seconds=g.MAX_DURATION_S, benign_seconds=5))
        with self.assertRaisesRegex(SystemExit, "packets exceeds"):
            g.generate(_args(out=self.out, flood_seconds=60, flood_pps=40000, benign_seconds=0))

    def test_opens_no_socket(self):
        # The generator must never touch the network: fail if socket.socket is constructed.
        import socket
        real = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(AssertionError("generator opened a socket"))
        try:
            g.generate(_args(out=self.out))
        finally:
            socket.socket = real
        self.assertTrue(os.path.exists(self.out))

    def test_produces_readable_pcap_with_flood_characteristics(self):
        counts = g.generate(_args(out=self.out))
        self.assertEqual(counts["total"], counts["benign"] + counts["flood"])
        # The flood must have far more than the model's 511-unique-source-port basis.
        self.assertGreater(counts["flood_unique_src_ports"], 511)
        # The file is a real PCAP the sensor's own reader + decoder can parse into packets.
        syn_only = 0
        total = 0
        src_ports = set()
        with open(self.out, "rb") as stream:
            for raw in read_capture(stream, Stats()):
                pkt = decode(raw.ts_ns, raw.linktype, raw.data)
                if not isinstance(pkt, Packet):
                    continue
                total += 1
                if pkt.proto == 6 and (pkt.tcp_flags & 0x02) and not (pkt.tcp_flags & 0x10):
                    syn_only += 1
                    src_ports.add(pkt.sport)
        self.assertEqual(total, counts["total"], "every generated packet decodes")
        self.assertGreater(len(src_ports), 511, "the capture carries many distinct SYN source ports")
        self.assertGreater(syn_only, counts["flood"] * 0.9, "the flood is SYN-only")


if __name__ == "__main__":
    unittest.main()
