import unittest

from netsensor.flows import (
    ACTIVE_TIMEOUT_NS,
    IDLE_TIMEOUT_NS,
    FlowTable,
    FragmentTable,
)
from netsensor.packet import decode
from netsensor.stats import Stats
from tests import pcap_builder as pb


def run(frames, expire=True):
    stats = Stats()
    records = []
    table = FlowTable(stats, records.append)
    frags = FragmentTable(stats)
    new_flags = []
    for ts, frame in frames:
        pkt = frags.resolve(decode(ts, 1, frame))
        _, is_new = table.update(pkt)
        new_flags.append(is_new)
        if expire:
            table.expire(ts)
    table.flush()
    return records, new_flags, stats


class FlowTableTest(unittest.TestCase):
    def test_tcp_session_is_one_bidirectional_flow(self):
        records, new_flags, _ = run(pb.tcp_session(pb.S))
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual((r["initiator_ip"], r["initiator_port"]), (pb.CLIENT, 50000))
        self.assertEqual((r["responder_ip"], r["responder_port"]), (pb.SERVER, 80))
        self.assertEqual((r["fwd_packets"], r["bwd_packets"]), (5.0, 3.0))
        self.assertEqual(r["end_reason"], "fin")
        self.assertEqual(r["start_observed"], "yes")
        self.assertEqual((r["syn_count"], r["synack_count"]), (1.0, 1.0))
        self.assertEqual(new_flags, [True] + [False] * 7)
        self.assertAlmostEqual(r["duration_ms"], 90.0)

    def test_final_ack_after_close_does_not_make_a_new_flow(self):
        # The last packet of tcp_session is the ACK after both FINs.
        records, new_flags, _ = run(pb.tcp_session(pb.S))
        self.assertEqual(len(records), 1)
        self.assertFalse(new_flags[-1])

    def test_syn_on_a_closed_key_starts_a_new_flow(self):
        frames = pb.tcp_session(pb.S) + pb.tcp_session(pb.S + 200 * pb.MS)
        records, new_flags, _ = run(frames)
        self.assertEqual(len(records), 2)
        self.assertEqual(sum(new_flags), 2)

    def test_flow_first_seen_at_synack_is_oriented_to_the_client(self):
        frames = pb.tcp_session(pb.S)[1:]  # capture missed the SYN
        records, _, _ = run(frames)
        self.assertEqual(records[0]["initiator_ip"], pb.CLIENT)
        self.assertEqual(records[0]["start_observed"], "no")

    def test_mid_stream_capture_is_flagged_incomplete_at_eof(self):
        frames = pb.tcp_session(pb.S)[3:5]  # request and reply only
        records, _, _ = run(frames)
        self.assertEqual(records[0]["start_observed"], "no")
        self.assertEqual(records[0]["end_reason"], "eof")

    def test_idle_gap_splits_the_flow(self):
        a = pb.dns_exchange(pb.S)
        b = pb.dns_exchange(pb.S + IDLE_TIMEOUT_NS + 10 * pb.S)
        records, new_flags, _ = run(a + b)
        self.assertEqual([r["end_reason"] for r in records], ["idle", "eof"])
        self.assertEqual(sum(new_flags), 2)

    def test_active_timeout_continues_without_counting_a_new_flow(self):
        frames = []
        t = pb.S
        while t < pb.S + ACTIVE_TIMEOUT_NS + 20 * pb.S:
            frames += pb.dns_exchange(t)
            t += 10 * pb.S
        records, new_flags, _ = run(frames)
        self.assertEqual(records[0]["end_reason"], "active")
        self.assertTrue(records[1]["continued"])
        self.assertEqual(sum(new_flags), 1)

    def test_udp_and_icmp_have_no_handshake(self):
        records, _, _ = run(pb.dns_exchange(pb.S) + pb.ping(2 * pb.S))
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r["start_observed"] == "na" for r in records))
        self.assertEqual([r["fwd_packets"] + r["bwd_packets"] for r in records], [2.0, 2.0])

    def test_fragments_are_attributed_to_their_datagram_flow(self):
        records, _, stats = run(pb.fragmented_udp(pb.S))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["fragment_count"], 2.0)
        self.assertEqual(stats.get("fragment_attributed"), 1)

    def test_orphan_fragment_keeps_unknown_ports(self):
        records, _, stats = run(pb.fragmented_udp(pb.S)[1:])
        self.assertEqual(stats.get("orphan_fragment"), 1)
        self.assertEqual(records[0]["initiator_port"], -1)

    def test_single_packet_flow_has_nan_rates_not_infinity(self):
        records, _, _ = run(pb.dns_exchange(pb.S)[:1])
        r = records[0]
        self.assertNotEqual(r["pkts_per_s"], r["pkts_per_s"])  # NaN
        self.assertEqual(r["duration_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
