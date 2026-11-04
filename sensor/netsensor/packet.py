"""
Decode one captured frame into the few header fields the extractor uses.

Standard library only. Every way a frame can fail is a named reason, counted
by the caller; nothing raises past `decode()`.

Decisions:
  - IPv4 and IPv6 are both supported. IPv6 extension headers are walked (at
    most MAX_IPV6_EXT_HEADERS); ESP and "no next header" end the walk.
  - Packet size is the IP total length, not the frame length, so Ethernet and
    raw-IP captures measure the same thing. A zero length field (seen with
    segmentation offload on the capturing host) falls back to the captured
    length and is counted.
  - Fragments are not reassembled. A non-first fragment carries no transport
    header, so its ports are UNKNOWN (-1); the flow table may attribute it
    from the first fragment.
  - A valid IP header whose transport header is cut short (snap length,
    tiny first fragment) is KEPT with unknown ports, so volume features stay
    correct; it is counted as `l4_truncated`.
  - Checksums are not verified: NIC offload makes them unreliable in captures.
  - Ethernet trailer padding is ignored by trusting the IP length.
"""

import struct
from dataclasses import dataclass
from typing import Tuple, Union

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

UNKNOWN_PORT = -1

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
MAX_VLAN_TAGS = 4

MAX_IPV6_EXT_HEADERS = 8
_IPV6_EXT = {0, 43, 60}  # hop-by-hop, routing, destination options
_IPV6_FRAGMENT = 44
_IPV6_AH = 51

ICMP_ECHO_TYPES = {8, 0}  # request, reply
ICMPV6_ECHO_TYPES = {128, 129}


@dataclass(frozen=True)
class Packet:
    ts_ns: int
    version: int  # 4 or 6
    src: bytes
    dst: bytes
    proto: int
    ip_len: int
    sport: int  # UNKNOWN_PORT when not readable; 0 for protocols without ports
    dport: int
    tcp_flags: int
    is_fragment: bool
    first_fragment: bool
    frag_id: int
    l4_ok: bool
    icmp_type: int  # -1 unless ICMP/ICMPv6
    len_from_capture: bool  # the IP length field was 0; captured length used


@dataclass(frozen=True)
class Skip:
    """A frame that yields no packet. `malformed` False means not IP (ARP, LLDP…)."""

    reason: str
    malformed: bool


def decode(ts_ns: int, linktype: int, data: bytes) -> Union[Packet, Skip]:
    l3 = _link_payload(linktype, data)
    if isinstance(l3, Skip):
        return l3
    version_hint, offset = l3
    if offset >= len(data):
        return Skip("truncated_ip", True)
    version = data[offset] >> 4
    if version_hint and version != version_hint:
        return Skip("bad_ip_version", True)
    if version == 4:
        return _ipv4(ts_ns, data, offset)
    if version == 6:
        return _ipv6(ts_ns, data, offset)
    return Skip("bad_ip_version", True)


def _link_payload(linktype: int, data: bytes) -> Union[Tuple[int, int], Skip]:
    """(expected IP version or 0, offset of the IP header)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return Skip("truncated_link", True)
        ethertype = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        tags = 0
        while ethertype in VLAN_TYPES:
            tags += 1
            if tags > MAX_VLAN_TAGS or len(data) < offset + 4:
                return Skip("truncated_link", True)
            ethertype = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        return _by_ethertype(ethertype, offset)
    if linktype == LINKTYPE_RAW:
        return (0, 0)
    if linktype == LINKTYPE_IPV4:
        return (4, 0)
    if linktype == LINKTYPE_IPV6:
        return (6, 0)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return Skip("truncated_link", True)
        return _by_ethertype(struct.unpack_from("!H", data, 14)[0], 16)
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return Skip("truncated_link", True)
        return _by_ethertype(struct.unpack_from("!H", data, 0)[0], 20)
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return Skip("truncated_link", True)
        # The address family is in the CAPTURING host's byte order.
        for family in (struct.unpack_from("<I", data, 0)[0], struct.unpack_from(">I", data, 0)[0]):
            if family == 2:
                return (4, 4)
            if family in (24, 28, 30):
                return (6, 4)
        return Skip("non_ip", False)
    return Skip("unsupported_linktype", False)


def _by_ethertype(ethertype: int, offset: int) -> Union[Tuple[int, int], Skip]:
    if ethertype == ETH_IPV4:
        return (4, offset)
    if ethertype == ETH_IPV6:
        return (6, offset)
    return Skip("non_ip", False)


def _ipv4(ts_ns: int, data: bytes, off: int) -> Union[Packet, Skip]:
    captured = len(data) - off
    if captured < 20:
        return Skip("truncated_ip", True)
    ihl = (data[off] & 0x0F) * 4
    if ihl < 20:
        return Skip("bad_ipv4_header_length", True)
    if captured < ihl:
        return Skip("truncated_ip", True)
    total_len, frag_id, flags_frag = struct.unpack_from("!HHH", data, off + 2)
    proto = data[off + 9]
    src = bytes(data[off + 12 : off + 16])
    dst = bytes(data[off + 16 : off + 20])
    zero_len = total_len == 0
    if zero_len:
        total_len = captured
    elif total_len < ihl:
        return Skip("bad_ipv4_total_length", True)
    more = bool(flags_frag & 0x2000)
    frag_offset = (flags_frag & 0x1FFF) * 8
    is_fragment = more or frag_offset > 0
    first = frag_offset == 0
    # Only the bytes the IP length covers (drops Ethernet padding), and only
    # what was captured (snap length).
    l4_end = off + min(total_len, captured)
    l4 = data[off + ihl : l4_end]
    return _transport(
        ts_ns, 4, src, dst, proto, total_len, l4, is_fragment, first, frag_id,
        zero_len,
    )


def _ipv6(ts_ns: int, data: bytes, off: int) -> Union[Packet, Skip]:
    captured = len(data) - off
    if captured < 40:
        return Skip("truncated_ip", True)
    payload_len = struct.unpack_from("!H", data, off + 4)[0]
    next_header = data[off + 6]
    src = bytes(data[off + 8 : off + 24])
    dst = bytes(data[off + 24 : off + 40])
    zero_len = payload_len == 0
    total_len = captured if zero_len else 40 + payload_len
    end = off + min(total_len, captured)
    pos = off + 40
    is_fragment = False
    first = True
    frag_id = 0
    headers = 0
    while next_header in _IPV6_EXT or next_header in (_IPV6_FRAGMENT, _IPV6_AH):
        headers += 1
        if headers > MAX_IPV6_EXT_HEADERS:
            return Skip("too_many_ipv6_ext", True)
        if pos + 8 > end:
            return Skip("truncated_ipv6_ext", True)
        if next_header == _IPV6_FRAGMENT:
            offset_m = struct.unpack_from("!H", data, pos + 2)[0]
            frag_id = struct.unpack_from("!I", data, pos + 4)[0]
            frag_offset = (offset_m & 0xFFF8)
            is_fragment = True
            first = frag_offset == 0
            hdr_len = 8
        elif next_header == _IPV6_AH:
            hdr_len = (data[pos + 1] + 2) * 4
        else:
            hdr_len = (data[pos + 1] + 1) * 8
        next_header = data[pos]
        pos += hdr_len
        if pos > end:
            return Skip("truncated_ipv6_ext", True)
        if is_fragment and not first:
            break
    l4 = data[pos:end]
    return _transport(
        ts_ns, 6, src, dst, next_header, total_len, l4, is_fragment, first,
        frag_id, zero_len,
    )


def _transport(
    ts_ns: int,
    version: int,
    src: bytes,
    dst: bytes,
    proto: int,
    ip_len: int,
    l4: bytes,
    is_fragment: bool,
    first: bool,
    frag_id: int,
    zero_len: bool,
) -> Packet:
    sport = dport = UNKNOWN_PORT
    flags = 0
    icmp_type = -1
    l4_ok = False
    if is_fragment and not first:
        pass  # no transport header in this fragment
    elif proto == PROTO_TCP:
        if len(l4) >= 14:
            sport, dport = struct.unpack_from("!HH", l4, 0)
            flags = l4[13] & 0x3F
            # A data offset below 5 words is invalid, but ports and flags are
            # still where they always are.
            l4_ok = len(l4) >= 20 and (l4[12] >> 4) >= 5
    elif proto == PROTO_UDP:
        if len(l4) >= 8:
            sport, dport = struct.unpack_from("!HH", l4, 0)
            l4_ok = True
    elif proto in (PROTO_ICMP, PROTO_ICMPV6):
        if len(l4) >= 4:
            icmp_type = l4[0]
            echo = ICMP_ECHO_TYPES if proto == PROTO_ICMP else ICMPV6_ECHO_TYPES
            if icmp_type in echo and len(l4) >= 8:
                # Request and reply share the identifier, so they share a flow.
                ident = struct.unpack_from("!H", l4, 4)[0]
                sport = dport = ident
            else:
                sport = dport = 0
            l4_ok = True
    else:
        sport = dport = 0  # no port concept
        l4_ok = True
    return Packet(
        ts_ns=ts_ns,
        version=version,
        src=src,
        dst=dst,
        proto=proto,
        ip_len=ip_len,
        sport=sport,
        dport=dport,
        tcp_flags=flags,
        is_fragment=is_fragment,
        first_fragment=first,
        frag_id=frag_id,
        l4_ok=l4_ok,
        icmp_type=icmp_type,
        len_from_capture=zero_len,
    )
