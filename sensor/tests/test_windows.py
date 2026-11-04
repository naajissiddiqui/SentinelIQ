import math
import unittest

from netsensor.flows import FlowTable
from netsensor.packet import decode
from netsensor.schema import FEATURE_NAMES, KEY_COLUMNS, WINDOW_NS
from netsensor.stats import Stats
from netsensor.windows import WindowAggregator
from tests import pcap_builder as pb

T0 = 1_700_000_000 * pb.S  # on the 5 s grid


def run(frames):
    stats = Stats()
    rows = []
    flows = FlowTable(stats)
    agg = WindowAggregator(stats, rows.append)
    for ts, frame in frames:
        pkt = decode(ts, 1, frame)
        key, is_new = flows.update(pkt)
        agg.add(pkt, key, is_new)
    agg.finish()
    return rows, stats


def by_host(rows, host):
    return [r for r in rows if r["dst_ip"] == host]


class WindowTest(unittest.TestCase):
    def test_rows_have_exactly_the_schema_columns(self):
        rows, _ = run(pb.tcp_session(T0))
        for row in rows:
            self.assertEqual(list(row), KEY_COLUMNS + FEATURE_NAMES)

    def test_tcp_session_counts_for_the_server(self):
        rows, _ = run(pb.tcp_session(T0))
        (server,) = by_host(rows, pb.SERVER)
        self.assertEqual(server["in_packets"], 5.0)
        self.assertEqual(server["out_packets"], 3.0)
        self.assertEqual(server["tcp_syn_only_ratio"], 1 / 5)
        self.assertEqual(server["tcp_synack_reply_ratio"], 1.0)
        self.assertEqual(server["tcp_ack_only_ratio"], 2 / 5)
        self.assertEqual(server["flows_active"], 1.0)
        self.assertEqual(server["flows_new"], 1.0)
        self.assertEqual(server["unanswered_flow_share"], 0.0)
        self.assertEqual(server["unique_src"], 1.0)
        self.assertEqual(server["src_entropy_norm"], 0.0)
        self.assertEqual(server["in_tcp_share"], 1.0)
        self.assertEqual(server["in_len_min"], 40.0)

    def test_new_flow_is_counted_for_the_host_it_was_opened_to(self):
        rows, _ = run(pb.tcp_session(T0))
        (client,) = by_host(rows, pb.CLIENT)
        self.assertEqual(client["flows_new"], 0.0)

    def test_tcp_ratios_are_nan_without_tcp(self):
        rows, _ = run(pb.dns_exchange(T0))
        (resolver,) = by_host(rows, pb.RESOLVER)
        for name in ("tcp_syn_only_ratio", "tcp_rst_ratio", "tcp_synack_reply_ratio"):
            self.assertTrue(math.isnan(resolver[name]), name)
        self.assertEqual(resolver["in_udp_share"], 1.0)

    def test_single_inbound_packet_has_nan_inter_arrival(self):
        rows, _ = run(pb.dns_exchange(T0))
        (resolver,) = by_host(rows, pb.RESOLVER)
        self.assertTrue(math.isnan(resolver["in_iat_mean_ms"]))
        self.assertTrue(math.isnan(resolver["in_iat_cv"]))

    def test_slot_boundary_is_on_the_packet_time_grid(self):
        frames = [
            (T0 + WINDOW_NS - 1, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 53)),
            (T0 + WINDOW_NS, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 53)),
        ]
        rows, _ = run(frames)
        self.assertEqual([r["window_start_ns"] for r in rows], [T0, T0 + WINDOW_NS])
        self.assertEqual(rows[0]["window_start_utc"], "2023-11-14T22:13:20Z")

    def test_late_packet_is_counted_and_left_out(self):
        frames = [
            (T0 + 1 * pb.S, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 53)),
            (T0 + 20 * pb.S, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 53)),
            (T0 + 2 * pb.S, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 53)),  # slot closed
        ]
        rows, stats = run(frames)
        self.assertEqual(stats.get("late_packet"), 1)
        self.assertEqual(rows[0]["in_packets"], 1.0)

    def test_reordering_within_the_grace_period_is_kept(self):
        frames = [
            (T0 + 3 * pb.S, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 53)),
            (T0 + 1 * pb.S, pb.udp_frame(pb.CLIENT2, pb.RESOLVER, 1, 53)),
        ]
        rows, stats = run(frames)
        self.assertEqual(rows[0]["in_packets"], 2.0)
        self.assertEqual(rows[0]["in_iat_min_ms"], 0.0)
        self.assertEqual(stats.get("out_of_order_packet"), 1)
        self.assertEqual(stats.get("late_packet"), 0)

    def test_baseline_is_nan_without_history_then_compares_to_the_median(self):
        frames = []
        for i in range(3):
            frames += pb.dns_exchange(T0 + i * WINDOW_NS + pb.S, sport=53000 + i)
        rows, _ = run(frames)
        resolver = by_host(rows, pb.RESOLVER)
        self.assertEqual(len(resolver), 3)
        self.assertTrue(math.isnan(resolver[0]["in_pps_ratio_baseline"]))
        # Two earlier slots at 0.2 pps, ten silent ones: median 0, floored at 1.
        self.assertEqual(resolver[2]["in_pps_ratio_baseline"], 0.2)
        self.assertEqual(resolver[2]["unique_src_ratio_baseline"], 1.0)

    def test_unanswered_and_single_packet_flows(self):
        frames = pb.tcp_session(T0)[:1]  # a SYN nobody answered
        rows, _ = run(frames)
        (server,) = by_host(rows, pb.SERVER)
        self.assertEqual(server["unanswered_flow_share"], 1.0)
        self.assertEqual(server["single_packet_flow_share"], 1.0)
        self.assertEqual(server["tcp_synack_reply_ratio"], 0.0)

    def test_hosts_that_only_send_get_no_row(self):
        rows, _ = run(pb.dns_exchange(T0)[:1])
        self.assertEqual([r["dst_ip"] for r in rows], [pb.RESOLVER])

    def test_fragment_share_and_percentiles(self):
        rows, _ = run(pb.fragmented_udp(T0))
        (client,) = by_host(rows, pb.CLIENT)
        self.assertEqual(client["in_fragment_share"], 1.0)
        self.assertEqual(client["in_len_p50"], 44.0)
        self.assertEqual(client["in_len_p95"], 44.0)
        self.assertEqual(client["in_len_min"], 44.0)

    def test_source_diversity(self):
        frames = pb.dns_exchange(T0, client=pb.CLIENT) + pb.dns_exchange(T0 + pb.S, client=pb.CLIENT2)
        rows, _ = run(frames)
        (resolver,) = by_host(rows, pb.RESOLVER)
        self.assertEqual(resolver["unique_src"], 2.0)
        self.assertEqual(resolver["unique_src_prefix"], 1.0)  # same /24
        self.assertEqual(resolver["src_entropy_norm"], 1.0)
        self.assertEqual(resolver["top_src_share"], 0.5)


if __name__ == "__main__":
    unittest.main()
