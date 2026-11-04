"""
Streaming reader for classic libpcap and pcapng capture files.

Standard library only. Yields packets in FILE ORDER with integer-nanosecond
timestamps taken from the capture, never from the clock, so the same file
always produces the same sequence.

What it handles explicitly:
  - classic pcap in both byte orders, microsecond and nanosecond variants;
  - pcapng sections, interfaces (link type and `if_tsresol` per interface),
    Enhanced Packet Blocks; Simple Packet Blocks carry no timestamp and are
    skipped and counted; other block types are skipped;
  - a zero-byte file or an unknown magic number: PcapFormatError (the file is
    not a capture at all);
  - a header-only capture: valid, yields nothing;
  - a record or block cut off by the end of the file, or with an impossible
    length: reading of THAT file stops, and the reason is counted. Classic
    pcap has no way to resynchronise after a corrupt length, so continuing
    would only invent packets.
"""

import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, Iterator, Optional

from .stats import Stats

# A record longer than this is a corrupt length, not a packet.
MAX_RECORD_BYTES = 256 * 1024 * 1024

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000),  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),  # big-endian, nanoseconds
}
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_BOM = 0x1A2B3C4D


class PcapFormatError(ValueError):
    """The file is not a readable capture (empty, or an unknown format)."""


@dataclass(frozen=True)
class RawPacket:
    ts_ns: int
    linktype: int
    data: bytes
    orig_len: int
    file_index: int
    record_index: int


def read_capture(
    stream: BinaryIO, stats: Stats, file_index: int = 0
) -> Iterator[RawPacket]:
    head = stream.read(4)
    if len(head) == 0:
        raise PcapFormatError("empty file: no capture header")
    if len(head) < 4:
        raise PcapFormatError("file too short for a capture header")
    if head in _PCAP_MAGICS:
        yield from _read_pcap(stream, head, stats, file_index)
        return
    if struct.unpack("<I", head)[0] == _PCAPNG_SHB:
        yield from _read_pcapng(stream, head, stats, file_index)
        return
    raise PcapFormatError(f"unknown capture magic {head.hex()}")


def _read_pcap(
    stream: BinaryIO, magic: bytes, stats: Stats, file_index: int
) -> Iterator[RawPacket]:
    endian, frac_to_ns = _PCAP_MAGICS[magic]
    rest = stream.read(20)
    if len(rest) < 20:
        raise PcapFormatError("truncated pcap global header")
    _vmaj, _vmin, _zone, _sigfigs, _snaplen, network = struct.unpack(
        endian + "HHiIII", rest
    )
    # The upper bits may carry FCS information in newer writers.
    linktype = network & 0xFFFF
    frac_limit = 1_000_000 if frac_to_ns == 1_000 else 1_000_000_000
    record_header = struct.Struct(endian + "IIII")
    index = 0
    while True:
        hdr = stream.read(16)
        if not hdr:
            return
        if len(hdr) < 16:
            stats.add("truncated_record")
            return
        ts_sec, ts_frac, incl_len, orig_len = record_header.unpack(hdr)
        if incl_len > MAX_RECORD_BYTES:
            stats.add("corrupt_record_length")
            return
        data = stream.read(incl_len)
        if len(data) < incl_len:
            stats.add("truncated_record")
            return
        index += 1
        stats.add("records_read")
        if ts_frac >= frac_limit:
            stats.add("bad_timestamp")
            continue
        yield RawPacket(
            ts_sec * 1_000_000_000 + ts_frac * frac_to_ns,
            linktype,
            data,
            max(orig_len, incl_len),
            file_index,
            index,
        )


def _tsresol_to_ns(ticks: int, resol: Optional[int]) -> int:
    # Default resolution is microseconds (if_tsresol absent).
    if resol is None:
        return ticks * 1_000
    exponent = resol & 0x7F
    if resol & 0x80:  # power of two
        return (ticks * 1_000_000_000) >> exponent
    if exponent <= 9:
        return ticks * 10 ** (9 - exponent)
    return ticks // 10 ** (exponent - 9)


def _read_pcapng(
    stream: BinaryIO, first4: bytes, stats: Stats, file_index: int
) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: Dict[int, tuple] = {}
    index = 0
    pending_type = first4
    while True:
        type_bytes = pending_type if pending_type is not None else stream.read(4)
        pending_type = None
        if not type_bytes:
            return
        if len(type_bytes) < 4:
            stats.add("truncated_block")
            return
        len_bytes = stream.read(4)
        if len(len_bytes) < 4:
            stats.add("truncated_block")
            return

        if struct.unpack("<I", type_bytes)[0] == _PCAPNG_SHB:
            # A new section: its byte-order magic decides the endianness of
            # everything up to the next section header, the length included.
            bom = stream.read(4)
            if len(bom) < 4:
                stats.add("truncated_block")
                return
            if struct.unpack("<I", bom)[0] == _PCAPNG_BOM:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == _PCAPNG_BOM:
                endian = ">"
            else:
                raise PcapFormatError("pcapng section header with an invalid byte-order magic")
            total_len = struct.unpack(endian + "I", len_bytes)[0]
            if total_len < 28 or total_len % 4 or total_len > MAX_RECORD_BYTES:
                stats.add("corrupt_block_length")
                return
            body = stream.read(total_len - 12)
            if len(body) < total_len - 12:
                stats.add("truncated_block")
                return
            interfaces = {}
            continue

        block_type = struct.unpack(endian + "I", type_bytes)[0]
        total_len = struct.unpack(endian + "I", len_bytes)[0]
        if total_len < 12 or total_len % 4 or total_len > MAX_RECORD_BYTES:
            stats.add("corrupt_block_length")
            return
        body = stream.read(total_len - 8)
        if len(body) < total_len - 8:
            stats.add("truncated_block")
            return
        trailer = struct.unpack(endian + "I", body[-4:])[0]
        if trailer != total_len:
            stats.add("corrupt_block_length")
            return
        body = body[:-4]

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                stats.add("corrupt_block_length")
                return
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            interfaces[len(interfaces)] = (linktype, _if_tsresol(body[8:], endian))
        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                stats.add("corrupt_block_length")
                return
            if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if cap_len > len(body) - 20:
                stats.add("corrupt_block_length")
                return
            index += 1
            stats.add("records_read")
            if if_id not in interfaces:
                stats.add("unknown_interface")
                continue
            linktype, resol = interfaces[if_id]
            ticks = (ts_high << 32) | ts_low
            yield RawPacket(
                _tsresol_to_ns(ticks, resol),
                linktype,
                bytes(body[20 : 20 + cap_len]),
                max(orig_len, cap_len),
                file_index,
                index,
            )
        elif block_type == 3:  # Simple Packet Block: no timestamp
            index += 1
            stats.add("records_read")
            stats.add("no_timestamp")
        else:
            stats.add("skipped_block")


def _if_tsresol(options: bytes, endian: str) -> Optional[int]:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos : pos + 4])
        if code == 0:
            return None
        value = options[pos + 4 : pos + 4 + length]
        if code == 9 and length >= 1:
            return value[0]
        pos += 4 + ((length + 3) & ~3)
    return None
