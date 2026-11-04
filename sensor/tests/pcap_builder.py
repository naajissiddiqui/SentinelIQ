"""
TEST-ONLY helpers that hand-build a few BENIGN packets for parser unit tests.

Ordinary traffic only: one TCP connection (handshake, a request, a reply,
orderly close), a DNS-style UDP query and answer, an ICMP echo and its reply,
an IPv6 UDP exchange, and one UDP datagram split into two fragments. Addresses
are from the documentation ranges (RFC 5737, RFC 3849). Nothing here is sent
anywhere: bytes are written to temporary files and read back.

These are NOT training or evaluation data and NOT demonstration evidence.
"""

import ipaddress
import struct
from typing import Iterable, List, Optional, Tuple

ETH_SRC = b"\x02\x00\x00\x00\x00\x01"
ETH_DST = b"\x02\x00\x00\x00\x00\x02"

CLIENT = "192.0.2.10"
CLIENT2 = "192.0.2.11"
SERVER = "198.51.100.20"
RESOLVER = "203.0.113.53"
CLIENT6 = "2001:db8::10"
SERVER6 = "2001:db8::20"

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

S = 1_000_000_000  # one second in ns
MS = 1_000_000


def _ip(addr: str) -> bytes:
    return ipaddress.ip_address(addr).packed


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1,
         flags_frag: int = 0, total_len: Optional[int] = None) -> bytes:
    length = 20 + len(payload) if total_len is None else total_len
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, length, ident, flags_frag, 64, proto, 0, _ip(src), _ip(dst)
    )
    return header + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, ext: bytes = b"") -> bytes:
    header = struct.pack("!IHBB16s16s", 0x60000000, len(ext) + len(payload), next_header, 64, _ip(src), _ip(dst))
    return header + ext + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 0, ack: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(request: bool, ident: int, seq: int, payload: bytes = b"ping") -> bytes:
    return struct.pack("!BBHHH", 8 if request else 0, 0, 0, ident, seq) + payload


def ether(l3: bytes, ethertype: int = 0x0800, vlan: Optional[int] = None) -> bytes:
    if vlan is not None:
        return ETH_DST + ETH_SRC + struct.pack("!HH", 0x8100, vlan) + struct.pack("!H", ethertype) + l3
    return ETH_DST + ETH_SRC + struct.pack("!H", ethertype) + l3


def tcp_frame(src, dst, sport, dport, flags, payload=b""):
    return ether(ipv4(src, dst, 6, tcp(sport, dport, flags, payload)))


def udp_frame(src, dst, sport, dport, payload=b""):
    return ether(ipv4(src, dst, 17, udp(sport, dport, payload)))


def tcp_session(t0: int, client=CLIENT, server=SERVER, sport=50000, dport=80) -> List[Tuple[int, bytes]]:
    """One ordinary HTTP-style connection: handshake, request, reply, close."""
    c, s = client, server
    return [
        (t0 + 0 * MS, tcp_frame(c, s, sport, dport, SYN)),
        (t0 + 10 * MS, tcp_frame(s, c, dport, sport, SYN | ACK)),
        (t0 + 20 * MS, tcp_frame(c, s, sport, dport, ACK)),
        (t0 + 30 * MS, tcp_frame(c, s, sport, dport, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (t0 + 60 * MS, tcp_frame(s, c, dport, sport, PSH | ACK, b"HTTP/1.1 200 OK\r\n\r\nhello")),
        (t0 + 70 * MS, tcp_frame(c, s, sport, dport, FIN | ACK)),
        (t0 + 80 * MS, tcp_frame(s, c, dport, sport, FIN | ACK)),
        (t0 + 90 * MS, tcp_frame(c, s, sport, dport, ACK)),
    ]


def dns_exchange(t0: int, client=CLIENT, resolver=RESOLVER, sport=53000) -> List[Tuple[int, bytes]]:
    return [
        (t0, udp_frame(client, resolver, sport, 53, b"\x12\x34query")),
        (t0 + 5 * MS, udp_frame(resolver, client, 53, sport, b"\x12\x34answer")),
    ]


def ping(t0: int, client=CLIENT, server=SERVER, ident=7) -> List[Tuple[int, bytes]]:
    return [
        (t0, ether(ipv4(client, server, 1, icmp_echo(True, ident, 1)))),
        (t0 + 2 * MS, ether(ipv4(server, client, 1, icmp_echo(False, ident, 1)))),
    ]


def ipv6_udp_exchange(t0: int) -> List[Tuple[int, bytes]]:
    return [
        (t0, ether(ipv6(CLIENT6, SERVER6, 17, udp(40000, 123, b"time?")), 0x86DD)),
        (t0 + 3 * MS, ether(ipv6(SERVER6, CLIENT6, 17, udp(123, 40000, b"time!")), 0x86DD)),
    ]


def fragmented_udp(t0: int, src=RESOLVER, dst=CLIENT, ident=0x4242) -> List[Tuple[int, bytes]]:
    """One benign UDP datagram (a large answer) split into two IPv4 fragments."""
    datagram = udp(53, 53000, b"A" * 40)  # 48 bytes of UDP
    first, rest = datagram[:24], datagram[24:]
    return [
        (t0, ether(ipv4(src, dst, 17, first, ident=ident, flags_frag=0x2000))),
        (t0 + 1 * MS, ether(ipv4(src, dst, 17, rest, ident=ident, flags_frag=24 // 8))),
    ]


# --- capture files -----------------------------------------------------------

def pcap_bytes(packets: Iterable[Tuple[int, bytes]], linktype: int = 1, nanos: bool = False,
               big_endian: bool = False) -> bytes:
    e = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    out = [struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)]
    for ts_ns, frame in packets:
        sec, rem = divmod(ts_ns, S)
        frac = rem if nanos else rem // 1000
        out.append(struct.pack(e + "IIII", sec, frac, len(frame), len(frame)) + frame)
    return b"".join(out)


def _block(block_type: int, body: bytes) -> bytes:
    body = body + b"\x00" * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def pcapng_bytes(packets: Iterable[Tuple[int, bytes]], linktype: int = 1,
                 tsresol: Optional[int] = None, extra_blocks: bytes = b"") -> bytes:
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = b""
    if tsresol is not None:
        options = struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb = _block(1, struct.pack("<HHI", linktype, 0, 65535) + options)
    divisor = 1 if tsresol == 9 else 1000  # default resolution is microseconds
    blocks = [shb, idb, extra_blocks]
    for ts_ns, frame in packets:
        ticks = ts_ns // divisor
        blocks.append(_block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame))
    return b"".join(blocks)


def simple_packet_block(frame: bytes) -> bytes:
    return _block(3, struct.pack("<I", len(frame)) + frame)
