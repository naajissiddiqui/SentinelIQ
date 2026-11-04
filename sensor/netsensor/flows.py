"""
Bidirectional flow tracking.

A flow is one conversation between two endpoints over one protocol. Both
directions share one canonical key, and the INITIATOR is the endpoint that sent
the first packet seen — except that a TCP flow first seen at its SYN-ACK is
oriented towards the client the SYN-ACK answers.

A flow ends on:
  - idle:   no packet for IDLE_TIMEOUT_NS;
  - active: it has lasted ACTIVE_TIMEOUT_NS. The conversation carries on as a
            new record with `continued` set, and is NOT counted as a new flow;
  - fin / rst: a FIN in both directions, or a RST. Packets within LINGER_NS
            afterwards (the final ACK, a repeated RST) are absorbed, so an
            ordinary close does not leave a stray one-packet flow behind. A
            SYN on a closed key starts a new flow at once (port reuse);
  - eof:    the capture ended while it was open. Such a record is INCOMPLETE:
            it ends where the capture did, not where the conversation did.

`start_observed` says whether the flow's beginning is in the capture: for TCP,
whether its first packet was a bare SYN ("no" means the capture started
mid-conversation); "na" for protocols without a handshake.

Ports and addresses are part of the KEY only. Nothing here turns them into a
feature (see schema.FLOW_FEATURE_NAMES).
"""

import ipaddress
import math
from collections import OrderedDict
from dataclasses import replace
from typing import Callable, Dict, Optional, Tuple

from .packet import (
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_TCP,
    PROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    UNKNOWN_PORT,
    Packet,
)
from .schema import SCHEMA_VERSION
from .stats import Stats

IDLE_TIMEOUT_NS = 120 * 1_000_000_000
ACTIVE_TIMEOUT_NS = 300 * 1_000_000_000
LINGER_NS = 1 * 1_000_000_000

FRAGMENT_TIMEOUT_NS = 30 * 1_000_000_000
MAX_FRAGMENT_ENTRIES = 65_536

Endpoint = Tuple[bytes, int]
FlowKey = Tuple[int, Endpoint, Endpoint]


def flow_key(pkt: Packet) -> FlowKey:
    a = (pkt.src, pkt.sport)
    b = (pkt.dst, pkt.dport)
    return (pkt.proto, a, b) if a <= b else (pkt.proto, b, a)


class FragmentTable:
    """
    Gives a non-first fragment the ports of its datagram's first fragment.

    Fragments are not reassembled (memory is bounded instead). A fragment
    whose first fragment has not been seen — lost, out of order, or older than
    FRAGMENT_TIMEOUT_NS — keeps UNKNOWN_PORT and is counted as an orphan.
    """

    def __init__(self, stats: Stats) -> None:
        self._stats = stats
        self._ports: "OrderedDict[tuple, Tuple[int, int, int]]" = OrderedDict()

    def resolve(self, pkt: Packet) -> Packet:
        if not pkt.is_fragment:
            return pkt
        key = (pkt.version, pkt.src, pkt.dst, pkt.proto, pkt.frag_id)
        if pkt.first_fragment:
            if pkt.sport != UNKNOWN_PORT:
                self._ports[key] = (pkt.sport, pkt.dport, pkt.ts_ns)
                self._ports.move_to_end(key)
                if len(self._ports) > MAX_FRAGMENT_ENTRIES:
                    self._ports.popitem(last=False)
                    self._stats.add("fragment_table_evicted")
            return pkt
        found = self._ports.get(key)
        if found is None or pkt.ts_ns - found[2] > FRAGMENT_TIMEOUT_NS:
            self._stats.add("orphan_fragment")
            return pkt
        self._stats.add("fragment_attributed")
        return replace(pkt, sport=found[0], dport=found[1])


class Flow:
    __slots__ = (
        "proto", "initiator", "responder", "first_ts", "last_ts",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
        "fwd_sq", "bwd_sq", "fwd_min", "fwd_max", "bwd_min", "bwd_max",
        "iat_n", "iat_sum", "iat_sq", "iat_min", "iat_max",
        "syn", "synack", "fin", "rst", "psh", "ack", "fragments",
        "fin_fwd", "fin_bwd", "closed_at", "close_reason",
        "continued", "start_observed",
    )

    def __init__(self, pkt: Packet, continued: bool, initiator: Optional[Endpoint] = None):
        self.proto = pkt.proto
        if initiator is None:
            initiator = (pkt.src, pkt.sport)
            if pkt.proto == PROTO_TCP and pkt.tcp_flags & TCP_SYN and pkt.tcp_flags & TCP_ACK:
                initiator = (pkt.dst, pkt.dport)
        self.initiator = initiator
        self.responder = (
            (pkt.dst, pkt.dport) if initiator == (pkt.src, pkt.sport) else (pkt.src, pkt.sport)
        )
        self.first_ts = self.last_ts = pkt.ts_ns
        self.fwd_pkts = self.bwd_pkts = self.fwd_bytes = self.bwd_bytes = 0
        self.fwd_sq = self.bwd_sq = 0
        self.fwd_min = self.bwd_min = None
        self.fwd_max = self.bwd_max = None
        self.iat_n = self.iat_sum = self.iat_sq = 0
        self.iat_min = self.iat_max = None
        self.syn = self.synack = self.fin = self.rst = self.psh = self.ack = 0
        self.fragments = 0
        self.fin_fwd = self.fin_bwd = False
        self.closed_at: Optional[int] = None
        self.close_reason: Optional[str] = None
        self.continued = continued
        if pkt.proto != PROTO_TCP:
            self.start_observed = "na"
        elif continued:
            self.start_observed = "no"
        else:
            bare_syn = pkt.tcp_flags & TCP_SYN and not pkt.tcp_flags & TCP_ACK
            self.start_observed = "yes" if bare_syn else "no"

    def add(self, pkt: Packet) -> None:
        if self.fwd_pkts + self.bwd_pkts > 0:
            iat = pkt.ts_ns - self.last_ts
            if iat < 0:
                iat = 0  # out of order within the capture
            self.iat_n += 1
            self.iat_sum += iat
            self.iat_sq += iat * iat
            self.iat_min = iat if self.iat_min is None else min(self.iat_min, iat)
            self.iat_max = iat if self.iat_max is None else max(self.iat_max, iat)
        self.last_ts = max(self.last_ts, pkt.ts_ns)
        size = pkt.ip_len
        forward = (pkt.src, pkt.sport) == self.initiator
        if forward:
            self.fwd_pkts += 1
            self.fwd_bytes += size
            self.fwd_sq += size * size
            self.fwd_min = size if self.fwd_min is None else min(self.fwd_min, size)
            self.fwd_max = size if self.fwd_max is None else max(self.fwd_max, size)
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += size
            self.bwd_sq += size * size
            self.bwd_min = size if self.bwd_min is None else min(self.bwd_min, size)
            self.bwd_max = size if self.bwd_max is None else max(self.bwd_max, size)
        if pkt.is_fragment:
            self.fragments += 1
        if pkt.proto == PROTO_TCP:
            f = pkt.tcp_flags
            if f & TCP_SYN:
                if f & TCP_ACK:
                    self.synack += 1
                else:
                    self.syn += 1
            if f & TCP_ACK:
                self.ack += 1
            if f & TCP_PSH:
                self.psh += 1
            if f & TCP_FIN:
                self.fin += 1
                if forward:
                    self.fin_fwd = True
                else:
                    self.fin_bwd = True
                if self.fin_fwd and self.fin_bwd and self.closed_at is None:
                    self.closed_at = pkt.ts_ns
                    self.close_reason = "fin"
            if f & TCP_RST:
                self.rst += 1
                if self.closed_at is None:
                    self.closed_at = pkt.ts_ns
                    self.close_reason = "rst"

    def record(self, end_reason: str) -> Dict[str, object]:
        duration_ns = self.last_ts - self.first_ts
        packets = self.fwd_pkts + self.bwd_pkts
        total_bytes = self.fwd_bytes + self.bwd_bytes
        seconds = duration_ns / 1e9
        return {
            "schema_version": SCHEMA_VERSION,
            "protocol": self.proto,
            "initiator_ip": str(ipaddress.ip_address(self.initiator[0])),
            "initiator_port": self.initiator[1],
            "responder_ip": str(ipaddress.ip_address(self.responder[0])),
            "responder_port": self.responder[1],
            "first_ts_ns": self.first_ts,
            "last_ts_ns": self.last_ts,
            "end_reason": end_reason,
            "continued": self.continued,
            "start_observed": self.start_observed,
            "duration_ms": duration_ns / 1e6,
            "fwd_packets": float(self.fwd_pkts),
            "bwd_packets": float(self.bwd_pkts),
            "fwd_bytes": float(self.fwd_bytes),
            "bwd_bytes": float(self.bwd_bytes),
            "fwd_len_mean": _mean(self.fwd_bytes, self.fwd_pkts),
            "fwd_len_std": _std(self.fwd_bytes, self.fwd_sq, self.fwd_pkts),
            "fwd_len_min": _num(self.fwd_min),
            "fwd_len_max": _num(self.fwd_max),
            "bwd_len_mean": _mean(self.bwd_bytes, self.bwd_pkts),
            "bwd_len_std": _std(self.bwd_bytes, self.bwd_sq, self.bwd_pkts),
            "bwd_len_min": _num(self.bwd_min),
            "bwd_len_max": _num(self.bwd_max),
            # NaN for a single instant: a rate over zero time is not a number.
            "pkts_per_s": packets / seconds if duration_ns > 0 else math.nan,
            "bytes_per_s": total_bytes / seconds if duration_ns > 0 else math.nan,
            "iat_mean_ms": _mean(self.iat_sum, self.iat_n) / 1e6,
            "iat_std_ms": _std(self.iat_sum, self.iat_sq, self.iat_n) / 1e6,
            "iat_min_ms": _num(self.iat_min) / 1e6,
            "iat_max_ms": _num(self.iat_max) / 1e6,
            "proto_tcp": 1.0 if self.proto == PROTO_TCP else 0.0,
            "proto_udp": 1.0 if self.proto == PROTO_UDP else 0.0,
            "proto_icmp": 1.0 if self.proto in (PROTO_ICMP, PROTO_ICMPV6) else 0.0,
            "syn_count": float(self.syn),
            "synack_count": float(self.synack),
            "fin_count": float(self.fin),
            "rst_count": float(self.rst),
            "psh_count": float(self.psh),
            "ack_count": float(self.ack),
            "fragment_count": float(self.fragments),
        }


def _num(value: Optional[int]) -> float:
    return math.nan if value is None else float(value)


def _mean(total: int, n: int) -> float:
    return total / n if n else math.nan


def _std(total: int, squares: int, n: int) -> float:
    """Population standard deviation from exact integer sums."""
    if not n:
        return math.nan
    variance = (squares * n - total * total) / (n * n)
    return math.sqrt(variance) if variance > 0 else 0.0


class FlowTable:
    def __init__(self, stats: Stats, on_flow: Optional[Callable[[Dict[str, object]], None]] = None):
        self._stats = stats
        self._on_flow = on_flow
        self._flows: "OrderedDict[FlowKey, Flow]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._flows)

    def update(self, pkt: Packet) -> Tuple[FlowKey, bool]:
        """Add a packet. Returns its flow key and whether it started a NEW flow."""
        key = flow_key(pkt)
        flow = self._flows.get(key)
        is_new = False
        if flow is not None:
            reason = self._ends_before(flow, pkt)
            if reason is not None:
                self._emit(flow, reason)
                del self._flows[key]
                if reason == "active":
                    flow = Flow(pkt, continued=True, initiator=flow.initiator)
                else:
                    flow = Flow(pkt, continued=False)
                    is_new = True
                self._flows[key] = flow
        else:
            flow = Flow(pkt, continued=False)
            self._flows[key] = flow
            is_new = True
        flow.add(pkt)
        self._flows.move_to_end(key)
        return key, is_new

    @staticmethod
    def _ends_before(flow: Flow, pkt: Packet) -> Optional[str]:
        if flow.closed_at is not None:
            bare_syn = pkt.tcp_flags & TCP_SYN and not pkt.tcp_flags & TCP_ACK
            if bare_syn or pkt.ts_ns - flow.closed_at > LINGER_NS:
                return flow.close_reason
            return None
        if pkt.ts_ns - flow.last_ts > IDLE_TIMEOUT_NS:
            return "idle"
        if pkt.ts_ns - flow.first_ts > ACTIVE_TIMEOUT_NS:
            return "active"
        return None

    def expire(self, now_ns: int) -> None:
        """Emit flows idle (or past their close linger) as of packet time `now_ns`."""
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            if flow.closed_at is not None and now_ns - flow.closed_at > LINGER_NS:
                reason = flow.close_reason
            elif now_ns - flow.last_ts > IDLE_TIMEOUT_NS:
                reason = flow.close_reason or "idle"
            else:
                # Least recently updated first, so nothing behind it is idle.
                # A closed flow behind it waits for the idle sweep or its key's
                # next packet; its record is the same either way.
                return
            self._emit(flow, reason)
            del self._flows[key]

    def flush(self) -> None:
        """End of capture: emit everything still open."""
        for flow in self._flows.values():
            self._emit(flow, flow.close_reason or "eof")
        self._flows.clear()

    def _emit(self, flow: Flow, reason: str) -> None:
        self._stats.add(f"flows_{reason}")
        if self._on_flow is not None:
            self._on_flow(flow.record(reason))
