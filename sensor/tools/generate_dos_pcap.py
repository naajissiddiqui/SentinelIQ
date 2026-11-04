#!/usr/bin/env python3
"""
generate_dos_pcap.py
====================
Writes a SYNTHETIC libpcap capture of a local-only DoS/DDoS traffic pattern, for the SentinelIQ
network sensor to extract and the trained model to score. This is the safe alternative to live
capture on a machine without Npcap: the existing sensor only reads PCAP FILES, so this produces a
real PCAP of real TCP/IP packets WITHOUT sending anything on any network.

SAFETY (by construction):
  - No sockets are opened and no packets are transmitted. Only a FILE is written.
  - Destination/source addresses must be loopback (127.0.0.0/8) or documentation ranges
    (TEST-NET 192.0.2/198.51.100/203.0.113); anything else is refused. Nothing is ever sent,
    but this keeps the capture honestly "local only".
  - Hard caps on duration, packets-per-second and total packets. A clean, bounded run.

The capture has two clearly separated segments so a demonstration shows genuine discrimination:
  1. a BENIGN preamble: low rate, few source ports, normal SYN/SYN-ACK/ACK mix;
  2. a FLOOD: high rate, many distinct source ports, SYN-only to one target port.

Usage:
  python -m tools.generate_dos_pcap --out OUT.pcap [--target-ip 127.0.0.1] [--target-port 80]
      [--flood-seconds 20] [--flood-pps 6000] [--benign-seconds 10] [--benign-pps 60]
"""
import argparse
import ipaddress
import os
import struct
import sys

LINKTYPE_ETHERNET = 1
PCAP_MAGIC_USEC = 0xA1B2C3D4

# Hard safety limits.
MAX_DURATION_S = 120
MAX_PPS = 50_000
MAX_PACKETS = 2_000_000

# Documentation / loopback ranges that are safe to name in an offline capture.
SAFE_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

ETH_SRC = bytes.fromhex("020000000001")
ETH_DST = bytes.fromhex("020000000002")


def _require_safe(ip: str, what: str) -> int:
    addr = ipaddress.ip_address(ip)
    if not any(addr in net for net in SAFE_NETS):
        raise SystemExit(
            f"refusing: {what} {ip} is not loopback or a documentation range. "
            "This tool only labels local/isolated addresses (even though it never sends packets)."
        )
    return int(addr)


def _ipv4(total_len: int, src: int, dst: int) -> bytes:
    # version/IHL, DSCP, total length, id, flags+frag (DF), ttl, proto=TCP(6), checksum=0 (the
    # sensor trusts IP length and does not verify the checksum), src, dst.
    return struct.pack(">BBHHHBBHII", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0, src, dst)


def _tcp(sport: int, dport: int, flags: int) -> bytes:
    # sport, dport, seq, ack, data-offset(5<<4), flags, window, checksum=0, urgent=0.
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 64240, 0, 0)


def _frame(src: int, dst: int, sport: int, dport: int, flags: int) -> bytes:
    tcp = _tcp(sport, dport, flags)
    ip = _ipv4(20 + len(tcp), src, dst)
    return ETH_DST + ETH_SRC + struct.pack(">H", 0x0800) + ip + tcp


def _record(ts_ns: int, frame: bytes) -> bytes:
    sec, usec = ts_ns // 1_000_000_000, (ts_ns % 1_000_000_000) // 1000
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def generate(args) -> dict:
    if args.flood_seconds + args.benign_seconds > MAX_DURATION_S:
        raise SystemExit(f"total duration exceeds the {MAX_DURATION_S}s cap")
    if args.flood_pps > MAX_PPS or args.benign_pps > MAX_PPS:
        raise SystemExit(f"pps exceeds the {MAX_PPS} cap")
    victim = _require_safe(args.target_ip, "target")
    attacker = _require_safe(args.attacker_ip, "attacker source")
    benign_peer = _require_safe(args.benign_peer_ip, "benign peer")

    est = args.flood_seconds * args.flood_pps + args.benign_seconds * args.benign_pps * 2
    if est > MAX_PACKETS:
        raise SystemExit(f"estimated {est} packets exceeds the {MAX_PACKETS} cap; lower the rate or duration")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    # Base time: a fixed value for reproducible tests, or "now" so a demo shows a current timestamp.
    # The capture is synthetic either way; a current timestamp never makes it "live".
    if args.now:
        import time
        t0 = (int(time.time()) - (args.flood_seconds + args.benign_seconds + 2)) * 1_000_000_000
    else:
        t0 = 1_600_000_000_000_000_000
    counts = {"benign": 0, "flood": 0, "flood_unique_src_ports": 0}
    seen_flood_ports: set = set()

    with open(args.out, "wb", buffering=1 << 20) as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

        # 1. BENIGN preamble: a handful of ports, a normal handshake-like mix, to one service port.
        step_ns = 1_000_000_000 // max(args.benign_pps, 1)
        ts = t0
        for i in range(args.benign_seconds * args.benign_pps):
            sport = 40000 + (i % 20)  # only ~20 distinct source ports
            flags = 0x02 if i % 3 == 0 else (0x12 if i % 3 == 1 else 0x10)  # SYN / SYN-ACK / ACK
            # alternate direction so there are real replies (benign two-way traffic)
            if i % 3 == 1:
                f.write(_record(ts, _frame(victim, benign_peer, args.target_port, sport, flags)))
            else:
                f.write(_record(ts, _frame(benign_peer, victim, sport, args.target_port, flags)))
            counts["benign"] += 1
            ts += step_ns

        # 2. FLOOD: SYN-only, many distinct ephemeral source ports, one attacker -> one victim port.
        flood_start = t0 + args.benign_seconds * 1_000_000_000 + 1_000_000_000  # 1s gap
        step_ns = 1_000_000_000 // max(args.flood_pps, 1)
        ts = flood_start
        port = 1024
        for _ in range(args.flood_seconds * args.flood_pps):
            f.write(_record(ts, _frame(attacker, victim, port, args.target_port, 0x02)))  # SYN only
            seen_flood_ports.add(port)
            counts["flood"] += 1
            port += 1
            if port > 65535:
                port = 1024
            ts += step_ns

    counts["flood_unique_src_ports"] = len(seen_flood_ports)
    counts["total"] = counts["benign"] + counts["flood"]
    counts["bytes"] = os.path.getsize(args.out)
    return counts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Write a synthetic local-only DoS/DDoS PCAP (no packets are sent).")
    p.add_argument("--out", required=True, help="output .pcap path")
    p.add_argument("--target-ip", default="127.0.0.1", help="victim address (loopback/doc range only)")
    p.add_argument("--target-port", type=int, default=80)
    p.add_argument("--attacker-ip", default="127.0.0.1", help="flood source address (loopback/doc range only)")
    p.add_argument("--benign-peer-ip", default="127.0.0.1", help="benign client address (loopback/doc range only)")
    p.add_argument("--flood-seconds", type=int, default=20)
    p.add_argument("--flood-pps", type=int, default=6000)
    p.add_argument("--benign-seconds", type=int, default=10)
    p.add_argument("--benign-pps", type=int, default=60)
    p.add_argument("--now", action="store_true", help="timestamp the capture ending ~now (synthetic, not live)")
    args = p.parse_args(argv)
    counts = generate(args)
    print(
        f"wrote {args.out}: {counts['total']} packets ({counts['bytes']} bytes); "
        f"benign {counts['benign']}, flood {counts['flood']} with {counts['flood_unique_src_ports']} distinct source ports"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
