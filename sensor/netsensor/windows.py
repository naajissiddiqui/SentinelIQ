"""
Five-second, per-destination window aggregation.

Every decoded packet is counted twice: INBOUND for the host it was sent to, and
OUTBOUND for the host that sent it. A row is emitted for each (slot, host) that
received at least one packet in the slot; the outbound side only supplies that
host's replies (out_packets, SYN-ACK replies, answered flows).

Slots are fixed on the epoch grid of PACKET time (slot = ts // WINDOW_NS), so
the same capture always yields the same windows whatever wall-clock time it is
processed at.

Order and lateness: packets are taken in file order. A slot closes once a
packet at least CLOSE_GRACE_NS past the slot's end has been seen. A packet for
a slot that has already closed is counted as `late_packet` and left out of the
windows (it still counts in its flow). Inter-arrival times are measured in
arrival order; a timestamp that goes backwards contributes 0 and is counted.

Rows are emitted in (slot, address family, address) order, and every float is
computed from exact integer sums, so output is reproducible byte for byte.
Addresses and ports are used for grouping and for COUNTS of distinct values
only; none becomes a feature value.
"""

import ipaddress
import math
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, List, Optional, Tuple

from .flows import FlowKey
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
from .schema import BASELINE_WINDOWS, SCHEMA_VERSION, WINDOW_NS, WINDOW_SECONDS
from .stats import Stats

CLOSE_GRACE_NS = 2 * 1_000_000_000

# Floors for the baseline ratios, so a quiet history does not divide by ~0.
PPS_FLOOR = 1.0
FLOW_RATE_FLOOR = 0.2
UNIQUE_SRC_FLOOR = 1.0

# How often (in closed slots) hosts with no recent history are forgotten.
HISTORY_PRUNE_EVERY = 120


class _Acc:
    __slots__ = (
        "in_pkts", "in_bytes", "in_sq", "lengths",
        "last_in_ts", "iat_n", "iat_sum", "iat_sq", "iat_min", "iat_max",
        "out_pkts", "out_bytes",
        "n_tcp", "n_udp", "n_icmp", "n_other", "n_frag",
        "syn_only", "rst", "fin", "psh", "ack_only", "out_synack",
        "src_counts", "src_prefixes", "src_ports", "dst_ports",
        "flows", "new_flows",
    )

    def __init__(self) -> None:
        self.in_pkts = self.in_bytes = self.in_sq = 0
        self.lengths: Counter = Counter()
        self.last_in_ts: Optional[int] = None
        self.iat_n = self.iat_sum = self.iat_sq = 0
        self.iat_min: Optional[int] = None
        self.iat_max: Optional[int] = None
        self.out_pkts = self.out_bytes = 0
        self.n_tcp = self.n_udp = self.n_icmp = self.n_other = self.n_frag = 0
        self.syn_only = self.rst = self.fin = self.psh = self.ack_only = 0
        self.out_synack = 0
        self.src_counts: Dict[bytes, int] = {}
        self.src_prefixes: set = set()
        self.src_ports: set = set()
        self.dst_ports: set = set()
        # flow key -> [inbound packets, inbound bytes, outbound packets]
        self.flows: Dict[FlowKey, List[int]] = {}
        self.new_flows = 0


def _prefix(addr: bytes) -> bytes:
    return addr[:3] if len(addr) == 4 else addr[:6]  # /24 or /48


def _percentile(lengths: Counter, n: int, p: float) -> float:
    """Nearest-rank percentile over an exact length histogram."""
    rank = max(1, math.ceil(p * n))
    seen = 0
    for value in sorted(lengths):
        seen += lengths[value]
        if seen >= rank:
            return float(value)
    return math.nan  # unreachable for n >= 1


def _std(total: int, squares: int, n: int) -> float:
    if not n:
        return math.nan
    variance = (squares * n - total * total) / (n * n)
    return math.sqrt(variance) if variance > 0 else 0.0


def _median(values: List[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


class WindowAggregator:
    def __init__(self, stats: Stats, on_window: Callable[[Dict[str, object]], None]):
        self._stats = stats
        self._on_window = on_window
        self._open: Dict[int, Dict[bytes, _Acc]] = {}
        self._closed_through: Optional[int] = None
        self._watermark: Optional[int] = None
        # host -> recent (slot, in_pps, new_flow_rate, unique_src), oldest first
        self._history: Dict[bytes, Deque[Tuple[int, float, float, float]]] = {}
        self._closed_count = 0

    def add(self, pkt: Packet, key: FlowKey, is_new_flow: bool) -> None:
        if self._watermark is None or pkt.ts_ns > self._watermark:
            self._watermark = pkt.ts_ns
            self._close_until(self._watermark)
        slot = pkt.ts_ns // WINDOW_NS
        if self._closed_through is not None and slot <= self._closed_through:
            self._stats.add("late_packet")
            return
        accs = self._open.setdefault(slot, {})
        inbound = accs.get(pkt.dst)
        if inbound is None:
            inbound = accs[pkt.dst] = _Acc()
        outbound = accs.get(pkt.src)
        if outbound is None:
            outbound = accs[pkt.src] = _Acc()
        self._add_inbound(inbound, pkt, key, is_new_flow)
        self._add_outbound(outbound, pkt, key)

    def _add_inbound(self, acc: _Acc, pkt: Packet, key: FlowKey, is_new_flow: bool) -> None:
        size = pkt.ip_len
        acc.in_pkts += 1
        acc.in_bytes += size
        acc.in_sq += size * size
        acc.lengths[size] += 1
        if acc.last_in_ts is not None:
            iat = pkt.ts_ns - acc.last_in_ts
            if iat < 0:
                self._stats.add("out_of_order_packet")
                iat = 0
            acc.iat_n += 1
            acc.iat_sum += iat
            acc.iat_sq += iat * iat
            acc.iat_min = iat if acc.iat_min is None else min(acc.iat_min, iat)
            acc.iat_max = iat if acc.iat_max is None else max(acc.iat_max, iat)
            acc.last_in_ts = max(acc.last_in_ts, pkt.ts_ns)
        else:
            acc.last_in_ts = pkt.ts_ns

        if pkt.proto == PROTO_TCP:
            acc.n_tcp += 1
            f = pkt.tcp_flags
            if f & TCP_SYN and not f & TCP_ACK:
                acc.syn_only += 1
            if f & TCP_RST:
                acc.rst += 1
            if f & TCP_FIN:
                acc.fin += 1
            if f & TCP_PSH:
                acc.psh += 1
            if f == TCP_ACK:
                acc.ack_only += 1
        elif pkt.proto == PROTO_UDP:
            acc.n_udp += 1
        elif pkt.proto in (PROTO_ICMP, PROTO_ICMPV6):
            acc.n_icmp += 1
        else:
            acc.n_other += 1
        if pkt.is_fragment:
            acc.n_frag += 1

        acc.src_counts[pkt.src] = acc.src_counts.get(pkt.src, 0) + 1
        acc.src_prefixes.add(_prefix(pkt.src))
        if pkt.proto in (PROTO_TCP, PROTO_UDP):
            if pkt.sport != UNKNOWN_PORT:
                acc.src_ports.add(pkt.sport)
            if pkt.dport != UNKNOWN_PORT:
                acc.dst_ports.add(pkt.dport)

        entry = acc.flows.get(key)
        if entry is None:
            entry = acc.flows[key] = [0, 0, 0]
        entry[0] += 1
        entry[1] += size
        if is_new_flow:
            acc.new_flows += 1

    @staticmethod
    def _add_outbound(acc: _Acc, pkt: Packet, key: FlowKey) -> None:
        acc.out_pkts += 1
        acc.out_bytes += pkt.ip_len
        if pkt.proto == PROTO_TCP and pkt.tcp_flags & TCP_SYN and pkt.tcp_flags & TCP_ACK:
            acc.out_synack += 1
        entry = acc.flows.get(key)
        if entry is None:
            entry = acc.flows[key] = [0, 0, 0]
        entry[2] += 1

    def _close_until(self, watermark: int) -> None:
        ready = sorted(s for s in self._open if (s + 1) * WINDOW_NS + CLOSE_GRACE_NS <= watermark)
        for slot in ready:
            self._close(slot)

    def advance_to(self, watermark_ns: int) -> None:
        """
        Close any windows that are complete as of `watermark_ns`, without needing a packet to arrive.
        Used by the live sensor to flush finished windows promptly when capture is briefly idle. Only
        advances the clock forward; a watermark in the past is ignored.
        """
        if self._watermark is None or watermark_ns > self._watermark:
            self._watermark = watermark_ns
        self._close_until(watermark_ns)

    def finish(self) -> None:
        for slot in sorted(self._open):
            self._close(slot)

    def _close(self, slot: int) -> None:
        accs = self._open.pop(slot)
        hosts = sorted(accs, key=lambda a: (len(a), a))
        rows = []
        for host in hosts:
            acc = accs[host]
            if acc.in_pkts == 0:
                continue
            rows.append((host, self._row(slot, host, acc)))
        # History is updated after every row of this slot is built, so a row
        # only ever sees earlier slots.
        for host, row in rows:
            history = self._history.setdefault(host, deque())
            history.append(
                (slot, row["in_pkts_per_s"], row["new_flows_per_s"], row["unique_src"])
            )
            while history and history[0][0] < slot - BASELINE_WINDOWS:
                history.popleft()
            self._on_window(row)
        self._closed_through = slot if self._closed_through is None else max(self._closed_through, slot)
        self._closed_count += 1
        if self._closed_count % HISTORY_PRUNE_EVERY == 0:
            stale = [h for h, q in self._history.items() if not q or q[-1][0] < slot - BASELINE_WINDOWS]
            for h in stale:
                del self._history[h]

    def _baseline(self, host: bytes, slot: int) -> Optional[Tuple[float, float, float]]:
        history = self._history.get(host)
        if not history:
            return None
        recent = [h for h in history if slot - BASELINE_WINDOWS <= h[0] < slot]
        if not recent:
            return None
        # Missing slots in the 60 s before are zero traffic, not unknown.
        pad = BASELINE_WINDOWS - len(recent)
        pps = [h[1] for h in recent] + [0.0] * pad
        nfr = [h[2] for h in recent] + [0.0] * pad
        usrc = [h[3] for h in recent] + [0.0] * pad
        return _median(pps), _median(nfr), _median(usrc)

    def _row(self, slot: int, host: bytes, acc: _Acc) -> Dict[str, object]:
        n = acc.in_pkts
        tcp = acc.n_tcp
        nan = math.nan
        iat_mean = acc.iat_sum / acc.iat_n if acc.iat_n else nan
        iat_std = _std(acc.iat_sum, acc.iat_sq, acc.iat_n)

        unique_src = len(acc.src_counts)
        counts = sorted(acc.src_counts.values())
        if unique_src > 1:
            entropy = -sum((c / n) * math.log2(c / n) for c in counts)
            entropy_norm = entropy / math.log2(unique_src)
        else:
            entropy_norm = 0.0

        active = [v for v in acc.flows.values() if v[0] > 0]
        flow_pkts = [v[0] for v in active]
        n_flows = len(active)
        fp_sum = sum(flow_pkts)
        fp_sq = sum(p * p for p in flow_pkts)

        pps = n / WINDOW_SECONDS
        new_rate = acc.new_flows / WINDOW_SECONDS
        base = self._baseline(host, slot)

        start_s = slot * WINDOW_SECONDS
        return {
            "schema_version": SCHEMA_VERSION,
            "window_start_ns": slot * WINDOW_NS,
            "window_start_utc": datetime.fromtimestamp(start_s, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "dst_ip": str(ipaddress.ip_address(host)),
            "in_packets": float(n),
            "in_bytes": float(acc.in_bytes),
            "in_pkts_per_s": pps,
            "in_bytes_per_s": acc.in_bytes / WINDOW_SECONDS,
            "out_packets": float(acc.out_pkts),
            "out_bytes": float(acc.out_bytes),
            "out_in_packet_ratio": acc.out_pkts / n,
            "in_len_mean": acc.in_bytes / n,
            "in_len_std": _std(acc.in_bytes, acc.in_sq, n),
            "in_len_min": float(min(acc.lengths)),
            "in_len_max": float(max(acc.lengths)),
            "in_len_p50": _percentile(acc.lengths, n, 0.50),
            "in_len_p95": _percentile(acc.lengths, n, 0.95),
            "in_iat_mean_ms": iat_mean / 1e6,
            "in_iat_std_ms": iat_std / 1e6,
            "in_iat_min_ms": float(acc.iat_min) / 1e6 if acc.iat_min is not None else nan,
            "in_iat_max_ms": float(acc.iat_max) / 1e6 if acc.iat_max is not None else nan,
            "in_iat_cv": iat_std / iat_mean if acc.iat_n and iat_mean > 0 else nan,
            "in_tcp_share": acc.n_tcp / n,
            "in_udp_share": acc.n_udp / n,
            "in_icmp_share": acc.n_icmp / n,
            "in_other_share": acc.n_other / n,
            "in_fragment_share": acc.n_frag / n,
            "tcp_syn_only_ratio": acc.syn_only / tcp if tcp else nan,
            "tcp_synack_reply_ratio": acc.out_synack / acc.syn_only if acc.syn_only else nan,
            "tcp_rst_ratio": acc.rst / tcp if tcp else nan,
            "tcp_fin_ratio": acc.fin / tcp if tcp else nan,
            "tcp_psh_ratio": acc.psh / tcp if tcp else nan,
            "tcp_ack_only_ratio": acc.ack_only / tcp if tcp else nan,
            "unique_src": float(unique_src),
            "unique_src_prefix": float(len(acc.src_prefixes)),
            "src_entropy_norm": entropy_norm,
            "top_src_share": counts[-1] / n,
            "unique_src_ports": float(len(acc.src_ports)),
            "unique_dst_ports": float(len(acc.dst_ports)),
            "flows_active": float(n_flows),
            "flows_new": float(acc.new_flows),
            "new_flows_per_s": new_rate,
            "pkts_per_flow_mean": fp_sum / n_flows,
            "pkts_per_flow_std": _std(fp_sum, fp_sq, n_flows),
            "pkts_per_flow_max": float(max(flow_pkts)),
            "bytes_per_flow_mean": sum(v[1] for v in active) / n_flows,
            "single_packet_flow_share": sum(1 for v in active if v[0] == 1 and v[2] == 0) / n_flows,
            "unanswered_flow_share": sum(1 for v in active if v[2] == 0) / n_flows,
            "in_pps_ratio_baseline": pps / max(base[0], PPS_FLOOR) if base else nan,
            "new_flow_rate_ratio_baseline": new_rate / max(base[1], FLOW_RATE_FLOOR) if base else nan,
            "unique_src_ratio_baseline": unique_src / max(base[2], UNIQUE_SRC_FLOOR) if base else nan,
        }
