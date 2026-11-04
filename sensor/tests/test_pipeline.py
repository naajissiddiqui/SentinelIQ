import csv
import ipaddress
import json
import os
import shutil
import struct
import tempfile
import unittest

from netsensor.__main__ import main
from netsensor.pcap_reader import PcapFormatError
from netsensor.pipeline import extract, extract_to_dir
from netsensor.schema import FEATURE_NAMES, format_value
from tests import pcap_builder as pb

T0 = 1_700_000_000 * pb.S


def benign_capture(t0=T0):
    """A few minutes of ordinary, hand-built traffic. Benign only."""
    frames = []
    for i in range(6):
        t = t0 + i * 7 * pb.S
        frames += pb.tcp_session(t + 100 * pb.MS, sport=50000 + i)
        frames += pb.dns_exchange(t + 2 * pb.S, sport=53000 + i)
        frames += pb.ping(t + 3 * pb.S, ident=i)
        frames += pb.ipv6_udp_exchange(t + 4 * pb.S)
    frames += pb.fragmented_udp(t0 + 50 * pb.S)
    frames += pb.dns_exchange(t0 + 60 * pb.S, client=pb.CLIENT2)
    return frames


def feature_matrix(frames):
    path = _write(pb.pcap_bytes(frames))
    try:
        rows = []
        extract([path], rows.append)
        # Sorted: relabelling addresses legitimately changes the ROW order
        # (rows are ordered by address), never the rows themselves.
        return sorted([format_value(r[n]) for n in FEATURE_NAMES] for r in rows)
    finally:
        os.unlink(path)


def as_text(rows):
    """Rows in their CSV text form. NaN != NaN, so raw dicts cannot be compared."""
    return [{k: format_value(v) for k, v in r.items()} for r in rows]


def _write(data: bytes, suffix=".pcap") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return path


# --- relabelling helpers for the invariance tests ---------------------------

def _remap_ipv4(frame: bytes, mapping) -> bytes:
    if struct.unpack_from("!H", frame, 12)[0] != 0x0800:
        return frame
    out = bytearray(frame)
    for off in (26, 30):
        addr = str(ipaddress.ip_address(bytes(out[off:off + 4])))
        out[off:off + 4] = ipaddress.ip_address(mapping.get(addr, addr)).packed
    return bytes(out)


def _remap_ports(frame: bytes, shift: int) -> bytes:
    if struct.unpack_from("!H", frame, 12)[0] != 0x0800:
        return frame
    proto = frame[23]
    flags_frag = struct.unpack_from("!H", frame, 20)[0]
    if proto not in (6, 17) or flags_frag & 0x1FFF:
        return frame
    out = bytearray(frame)
    sport, dport = struct.unpack_from("!HH", out, 34)
    struct.pack_into("!HH", out, 34, (sport + shift) % 65536, (dport + shift) % 65536)
    return bytes(out)


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _extract(self, frames, name="out", **kwargs):
        pcap = os.path.join(self.tmp, f"{name}.pcap")
        with open(pcap, "wb") as stream:
            stream.write(pb.pcap_bytes(frames))
        out = os.path.join(self.tmp, name)
        summary = extract_to_dir([pcap], out, **kwargs)
        return out, summary

    def test_same_input_gives_byte_identical_output(self):
        frames = benign_capture()
        a, _ = self._extract(frames, "a")
        b, _ = self._extract(frames, "b")
        for name in ("windows.csv", "flows.csv"):
            with open(os.path.join(a, name), "rb") as x, open(os.path.join(b, name), "rb") as y:
                self.assertEqual(x.read(), y.read(), name)

    def test_features_do_not_depend_on_addresses_ports_or_time_base(self):
        frames = benign_capture()
        reference = feature_matrix(frames)
        self.assertTrue(reference)

        mapping = {pb.CLIENT: "10.9.8.7", pb.CLIENT2: "10.9.8.6", pb.SERVER: "172.16.5.4",
                   pb.RESOLVER: "192.168.77.1"}
        relabelled = [(t, _remap_ipv4(f, mapping)) for t, f in frames]
        self.assertEqual(feature_matrix(relabelled), reference, "IP addresses")

        ported = [(t, _remap_ports(f, 1234)) for t, f in frames]
        self.assertEqual(feature_matrix(ported), reference, "port values")

        shifted = [(t + 1000 * pb.S * 5, f) for t, f in frames]  # whole windows later
        self.assertEqual(feature_matrix(shifted), reference, "time base")

    def test_split_files_equal_one_continuous_capture(self):
        frames = benign_capture()
        whole = os.path.join(self.tmp, "whole.pcap")
        part1 = os.path.join(self.tmp, "part1.pcap")
        part2 = os.path.join(self.tmp, "part2.pcap")
        mid = len(frames) // 2
        for path, chunk in ((whole, frames), (part1, frames[:mid]), (part2, frames[mid:])):
            with open(path, "wb") as stream:
                stream.write(pb.pcap_bytes(chunk))
        one, two = [], []
        extract([whole], one.append)
        extract([part1, part2], two.append)
        self.assertEqual(as_text(one), as_text(two))

    def test_pcapng_and_pcap_give_the_same_windows(self):
        frames = benign_capture()
        a = os.path.join(self.tmp, "a.pcap")
        b = os.path.join(self.tmp, "b.pcapng")
        with open(a, "wb") as stream:
            stream.write(pb.pcap_bytes(frames))
        with open(b, "wb") as stream:
            stream.write(pb.pcapng_bytes(frames))
        one, two = [], []
        extract([a], one.append)
        extract([b], two.append)
        self.assertEqual(as_text(one), as_text(two))

    def test_header_only_capture_produces_no_rows(self):
        out, summary = self._extract([], "empty")
        self.assertEqual(summary["windows_written"], 0)
        self.assertEqual(summary["flows_written"], 0)
        with open(os.path.join(out, "windows.csv"), encoding="utf-8") as stream:
            self.assertEqual(len(list(csv.reader(stream))), 1)  # header only

    def test_zero_byte_file_is_an_error(self):
        path = os.path.join(self.tmp, "zero.pcap")
        open(path, "wb").close()
        with self.assertRaises(PcapFormatError):
            extract([path], lambda row: None)

    def test_malformed_packets_are_counted_and_do_not_stop_processing(self):
        frames = pb.dns_exchange(T0)
        bad = (T0 + 1 * pb.MS, b"\x00" * 6)  # shorter than an Ethernet header
        arp = (T0 + 2 * pb.MS, pb.ether(b"\x00" * 28, ethertype=0x0806))
        _, summary = self._extract([frames[0], bad, arp, frames[1]], "bad")
        counts = summary["counts"]
        self.assertEqual(counts["malformed_truncated_link"], 1)
        self.assertEqual(counts["skipped_non_ip"], 1)
        self.assertEqual(counts["packets_decoded"], 2)
        self.assertEqual(summary["windows_written"], 2)

    def test_stats_file_records_schema_and_input_hash(self):
        out, summary = self._extract(benign_capture(), "s")
        with open(os.path.join(out, "stats.json"), encoding="utf-8") as stream:
            saved = json.load(stream)
        self.assertEqual(saved, json.loads(json.dumps(summary)))
        self.assertEqual(len(saved["inputs"][0]["sha256"]), 64)
        self.assertEqual(saved["schema_version"], "dos-window-v1")

    def test_existing_outputs_are_not_overwritten_without_force(self):
        out, _ = self._extract(benign_capture(), "o")
        pcap = os.path.join(self.tmp, "o.pcap")
        with self.assertRaises(FileExistsError):
            extract_to_dir([pcap], out)
        extract_to_dir([pcap], out, force=True)

    def test_cli(self):
        pcap = os.path.join(self.tmp, "cli.pcap")
        with open(pcap, "wb") as stream:
            stream.write(pb.pcap_bytes(benign_capture()))
        out = os.path.join(self.tmp, "cli-out")
        self.assertEqual(main(["extract", "--out-dir", out, "--no-hash", pcap]), 0)
        self.assertTrue(os.path.exists(os.path.join(out, "windows.csv")))
        self.assertEqual(main(["extract", "--out-dir", out, pcap]), 2)  # refuses to overwrite


if __name__ == "__main__":
    unittest.main()
