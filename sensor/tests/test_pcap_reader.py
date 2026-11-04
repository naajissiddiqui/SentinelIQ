import io
import struct
import unittest

from netsensor.pcap_reader import PcapFormatError, read_capture
from netsensor.stats import Stats
from tests import pcap_builder as pb


def read_all(data: bytes):
    stats = Stats()
    return list(read_capture(io.BytesIO(data), stats)), stats


class ClassicPcapTest(unittest.TestCase):
    def test_empty_file_is_not_a_capture(self):
        with self.assertRaises(PcapFormatError):
            read_all(b"")

    def test_unknown_magic_is_refused(self):
        with self.assertRaises(PcapFormatError):
            read_all(b"\x00\x01\x02\x03" + b"\x00" * 20)

    def test_header_only_capture_yields_nothing(self):
        packets, stats = read_all(pb.pcap_bytes([]))
        self.assertEqual(packets, [])
        self.assertEqual(stats.get("records_read"), 0)

    def test_microsecond_timestamps_become_nanoseconds(self):
        ts = 1_500_000_000 * pb.S + 123_456_000
        packets, _ = read_all(pb.pcap_bytes(pb.ping(ts)))
        self.assertEqual(packets[0].ts_ns, ts)
        self.assertEqual(packets[1].ts_ns, ts + 2 * pb.MS)

    def test_nanosecond_and_big_endian_variants(self):
        ts = 1_500_000_000 * pb.S + 123_456_789
        for big in (False, True):
            packets, _ = read_all(pb.pcap_bytes(pb.ping(ts), nanos=True, big_endian=big))
            self.assertEqual(packets[0].ts_ns, ts)
            self.assertEqual(packets[0].linktype, 1)

    def test_file_order_is_preserved_even_when_timestamps_go_backwards(self):
        a, b = pb.ping(10 * pb.S)
        packets, _ = read_all(pb.pcap_bytes([b, a]))
        self.assertEqual([p.ts_ns for p in packets], [b[0], a[0]])

    def test_truncated_record_stops_the_file_and_is_counted(self):
        data = pb.pcap_bytes(pb.ping(10 * pb.S))
        packets, stats = read_all(data[:-5])
        self.assertEqual(len(packets), 1)
        self.assertEqual(stats.get("truncated_record"), 1)

    def test_impossible_record_length_stops_the_file(self):
        header = pb.pcap_bytes([])
        bogus = struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        packets, stats = read_all(header + bogus)
        self.assertEqual(packets, [])
        self.assertEqual(stats.get("corrupt_record_length"), 1)

    def test_out_of_range_fraction_is_skipped_and_counted(self):
        frame = pb.ping(0)[0][1]
        header = pb.pcap_bytes([])
        record = struct.pack("<IIII", 5, 2_000_000, len(frame), len(frame)) + frame
        packets, stats = read_all(header + record)
        self.assertEqual(packets, [])
        self.assertEqual(stats.get("bad_timestamp"), 1)


class PcapngTest(unittest.TestCase):
    def test_default_microsecond_resolution(self):
        ts = 1_500_000_000 * pb.S + 5_000
        packets, _ = read_all(pb.pcapng_bytes(pb.ping(ts)))
        self.assertEqual([p.ts_ns for p in packets], [ts, ts + 2 * pb.MS])

    def test_nanosecond_resolution_option(self):
        ts = 1_500_000_000 * pb.S + 7
        packets, _ = read_all(pb.pcapng_bytes(pb.ping(ts), tsresol=9))
        self.assertEqual(packets[0].ts_ns, ts)

    def test_simple_packet_block_has_no_timestamp_and_is_skipped(self):
        spb = pb.simple_packet_block(pb.ping(0)[0][1])
        packets, stats = read_all(pb.pcapng_bytes(pb.ping(pb.S), extra_blocks=spb))
        self.assertEqual(len(packets), 2)
        self.assertEqual(stats.get("no_timestamp"), 1)

    def test_corrupt_block_length_stops_the_file(self):
        data = bytearray(pb.pcapng_bytes(pb.ping(pb.S)))
        data[-4:] = struct.pack("<I", 9999)  # trailer disagrees with the header
        packets, stats = read_all(bytes(data))
        self.assertEqual(len(packets), 1)
        self.assertEqual(stats.get("corrupt_block_length"), 1)


if __name__ == "__main__":
    unittest.main()
