import ipaddress
import struct
import unittest

from netsensor.packet import UNKNOWN_PORT, Packet, Skip, decode
from tests import pcap_builder as pb


def ip(addr):
    return ipaddress.ip_address(addr).packed


class DecodeTest(unittest.TestCase):
    def test_tcp_over_ipv4(self):
        pkt = decode(1, 1, pb.tcp_frame(pb.CLIENT, pb.SERVER, 50000, 80, pb.SYN))
        self.assertIsInstance(pkt, Packet)
        self.assertEqual((pkt.version, pkt.proto, pkt.sport, pkt.dport), (4, 6, 50000, 80))
        self.assertEqual((pkt.src, pkt.dst), (ip(pb.CLIENT), ip(pb.SERVER)))
        self.assertEqual(pkt.tcp_flags, pb.SYN)
        self.assertEqual(pkt.ip_len, 40)
        self.assertTrue(pkt.l4_ok)
        self.assertFalse(pkt.is_fragment)

    def test_udp_and_size_is_ip_total_length(self):
        pkt = decode(1, 1, pb.udp_frame(pb.CLIENT, pb.RESOLVER, 53000, 53, b"abc"))
        self.assertEqual((pkt.proto, pkt.sport, pkt.dport, pkt.ip_len), (17, 53000, 53, 31))

    def test_ethernet_padding_is_ignored(self):
        frame = pb.udp_frame(pb.CLIENT, pb.RESOLVER, 1, 2) + b"\x00" * 30
        self.assertEqual(decode(1, 1, frame).ip_len, 28)

    def test_icmp_echo_request_and_reply_share_identifier_as_key(self):
        req, rep = pb.ping(0, ident=99)
        a, b = decode(0, 1, req[1]), decode(0, 1, rep[1])
        self.assertEqual((a.sport, a.dport, b.sport, b.dport), (99, 99, 99, 99))
        self.assertEqual((a.icmp_type, b.icmp_type), (8, 0))

    def test_ipv6_udp(self):
        frame = pb.ipv6_udp_exchange(0)[0][1]
        pkt = decode(0, 1, frame)
        self.assertEqual((pkt.version, pkt.proto, pkt.sport, pkt.dport), (6, 17, 40000, 123))
        self.assertEqual(pkt.ip_len, 40 + 8 + 5)

    def test_ipv6_extension_header_is_walked(self):
        hop_by_hop = bytes([17, 0]) + b"\x00" * 6  # next = UDP, 8 bytes
        l3 = pb.ipv6(pb.CLIENT6, pb.SERVER6, 0, pb.udp(1, 2, b"x"), ext=hop_by_hop)
        pkt = decode(0, 1, pb.ether(l3, 0x86DD))
        self.assertEqual((pkt.proto, pkt.sport, pkt.dport), (17, 1, 2))

    def test_ipv6_truncated_extension_header_is_malformed(self):
        hop_by_hop = bytes([17, 5]) + b"\x00" * 6  # claims 48 bytes, has 8
        l3 = pb.ipv6(pb.CLIENT6, pb.SERVER6, 0, b"", ext=hop_by_hop)
        result = decode(0, 1, pb.ether(l3, 0x86DD))
        self.assertEqual(result, Skip("truncated_ipv6_ext", True))

    def test_vlan_tag_is_skipped(self):
        frame = pb.ether(pb.ipv4(pb.CLIENT, pb.SERVER, 17, pb.udp(1, 2)), vlan=100)
        self.assertEqual(decode(0, 1, frame).dport, 2)

    def test_non_ip_frame_is_skipped_not_malformed(self):
        arp = pb.ether(b"\x00" * 28, ethertype=0x0806)
        self.assertEqual(decode(0, 1, arp), Skip("non_ip", False))

    def test_unsupported_linktype(self):
        self.assertEqual(decode(0, 105, b"\x00" * 40), Skip("unsupported_linktype", False))

    def test_raw_ip_and_linux_sll_link_types(self):
        l3 = pb.ipv4(pb.CLIENT, pb.SERVER, 17, pb.udp(5, 6))
        self.assertEqual(decode(0, 101, l3).dport, 6)
        sll = b"\x00" * 14 + struct.pack("!H", 0x0800) + l3
        self.assertEqual(decode(0, 113, sll).dport, 6)

    def test_truncated_ethernet_and_ip_are_malformed(self):
        self.assertEqual(decode(0, 1, b"\x00" * 10), Skip("truncated_link", True))
        frame = pb.udp_frame(pb.CLIENT, pb.SERVER, 1, 2)
        self.assertEqual(decode(0, 1, frame[:14 + 12]), Skip("truncated_ip", True))

    def test_bad_ipv4_header_length_and_total_length(self):
        l3 = bytearray(pb.ipv4(pb.CLIENT, pb.SERVER, 17, pb.udp(1, 2)))
        l3[0] = 0x44  # IHL of 16 bytes
        self.assertEqual(decode(0, 101, bytes(l3)), Skip("bad_ipv4_header_length", True))
        short = pb.ipv4(pb.CLIENT, pb.SERVER, 17, pb.udp(1, 2), total_len=12)
        self.assertEqual(decode(0, 101, short), Skip("bad_ipv4_total_length", True))

    def test_wrong_version_nibble(self):
        l3 = bytearray(pb.ipv4(pb.CLIENT, pb.SERVER, 17, pb.udp(1, 2)))
        l3[0] = 0x55
        self.assertEqual(decode(0, 1, pb.ether(bytes(l3))), Skip("bad_ip_version", True))

    def test_zero_total_length_falls_back_to_captured_length(self):
        l3 = pb.ipv4(pb.CLIENT, pb.SERVER, 17, pb.udp(1, 2, b"abcd"), total_len=0)
        pkt = decode(0, 101, l3)
        self.assertTrue(pkt.len_from_capture)
        self.assertEqual(pkt.ip_len, 32)

    def test_truncated_tcp_header_is_kept_with_unknown_ports(self):
        l3 = pb.ipv4(pb.CLIENT, pb.SERVER, 6, pb.tcp(1, 2, pb.ACK)[:3])
        pkt = decode(0, 101, l3)
        self.assertIsInstance(pkt, Packet)
        self.assertEqual((pkt.sport, pkt.dport, pkt.l4_ok), (UNKNOWN_PORT, UNKNOWN_PORT, False))

    def test_fragments(self):
        first, second = pb.fragmented_udp(0)
        a, b = decode(0, 1, first[1]), decode(0, 1, second[1])
        self.assertTrue(a.is_fragment and a.first_fragment)
        self.assertEqual((a.sport, a.dport), (53, 53000))
        self.assertTrue(b.is_fragment and not b.first_fragment)
        self.assertEqual((b.sport, b.dport), (UNKNOWN_PORT, UNKNOWN_PORT))
        self.assertEqual(a.frag_id, b.frag_id)


if __name__ == "__main__":
    unittest.main()
