"""
PCAP file(s) -> decoded packets -> flows and 5-second destination windows.

Files are processed in the order given, as ONE continuous capture: flows and
windows carry across file boundaries, which is how the CIC datasets split a
day into many files. Sort the paths yourself; this module never reorders.

Labels never enter here. Ground truth is joined to the window rows in a
separate step, after scoring.
"""

import csv
import hashlib
import json
import os
from typing import Callable, Dict, Iterable, List, Optional

from .flows import FlowTable, FragmentTable
from .packet import Packet, Skip, decode
from .pcap_reader import read_capture
from .schema import (
    FEATURE_NAMES,
    FLOW_FEATURE_NAMES,
    FLOW_KEY_COLUMNS,
    KEY_COLUMNS,
    SCHEMA_VERSION,
    format_value,
    schema_fingerprint,
)
from .stats import Stats
from .windows import WindowAggregator

Sink = Callable[[Dict[str, object]], None]

# How often (in records) `should_stop` is consulted. A power of two keeps the
# check to one bitwise AND per packet.
STOP_CHECK_EVERY = 4096


class ExtractionAborted(RuntimeError):
    """`should_stop` asked the extraction to end. No complete output exists."""


def extract(
    paths: Iterable[str],
    on_window: Sink,
    on_flow: Optional[Sink] = None,
    stats: Optional[Stats] = None,
    on_file_done: Optional[Callable[[int, str, Stats, int], None]] = None,
    should_stop: Optional[Callable[[], Optional[str]]] = None,
) -> Stats:
    """
    `on_file_done(file_index, path, stats, live_flows)` runs after each file;
    `should_stop()` returning a reason raises ExtractionAborted. Neither changes
    what is extracted: they exist for job runners (progress, memory pressure).
    """
    stats = stats or Stats()
    fragments = FragmentTable(stats)
    flows = FlowTable(stats, on_flow)
    windows = WindowAggregator(stats, on_window)
    records = 0
    for file_index, path in enumerate(paths):
        with open(path, "rb", buffering=1 << 20) as stream:
            records = consume_raw(read_capture(stream, stats, file_index), fragments, flows, windows,
                                  stats, should_stop=should_stop, records=records)
        stats.add("files_read")
        if on_file_done is not None:
            on_file_done(file_index, path, stats, len(flows))
    windows.finish()
    flows.flush()
    return stats


def consume_raw(
    raw_iter: Iterable,
    fragments: "FragmentTable",
    flows: "FlowTable",
    windows: "WindowAggregator",
    stats: Stats,
    should_stop: Optional[Callable[[], Optional[str]]] = None,
    records: int = 0,
) -> int:
    """
    Decode a stream of raw frames (from a file OR a live interface) into the shared fragment, flow
    and window state. This is the one packet-processing loop used by both offline extraction and the
    live sensor, so they cannot diverge. It does NOT finish the windows/flows: the caller controls
    that (a file set finishes at the end; a live monitor finishes on shutdown). Returns the running
    record count.
    """
    for raw in raw_iter:
        records += 1
        if should_stop is not None and not records & (STOP_CHECK_EVERY - 1):
            reason = should_stop()
            if reason:
                raise ExtractionAborted(reason)
        result = decode(raw.ts_ns, raw.linktype, raw.data)
        if isinstance(result, Skip):
            prefix = "malformed_" if result.malformed else "skipped_"
            stats.add(prefix + result.reason)
            continue
        pkt: Packet = result
        stats.add("packets_decoded")
        stats.add(f"ipv{pkt.version}")
        if pkt.len_from_capture:
            stats.add("ip_length_from_capture")
        if pkt.is_fragment:
            stats.add("fragments")
        elif not pkt.l4_ok:
            stats.add("l4_unreadable")
        pkt = fragments.resolve(pkt)
        key, is_new = flows.update(pkt)
        windows.add(pkt, key, is_new)
        flows.expire(pkt.ts_ns)
    return records


class CsvSink:
    """Writes rows with a fixed header and deterministic value formatting."""

    def __init__(self, path: str, columns: List[str]):
        self._columns = columns
        self._file = open(path, "w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._file, lineterminator="\n")
        self._writer.writerow(columns)
        self.rows = 0

    def __call__(self, row: Dict[str, object]) -> None:
        self._writer.writerow([format_value(row[c]) for c in self._columns])
        self.rows += 1

    def close(self) -> None:
        self._file.close()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_to_dir(
    paths: List[str],
    out_dir: str,
    write_flows: bool = True,
    hash_inputs: bool = True,
    force: bool = False,
    on_file_done: Optional[Callable[[int, str, Stats, int], None]] = None,
    should_stop: Optional[Callable[[], Optional[str]]] = None,
    known_hashes: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    """`known_hashes` (path -> SHA-256) skips re-hashing inputs a caller already hashed."""
    os.makedirs(out_dir, exist_ok=True)
    targets = {
        "windows": os.path.join(out_dir, "windows.csv"),
        "flows": os.path.join(out_dir, "flows.csv"),
        "stats": os.path.join(out_dir, "stats.json"),
    }
    if not force:
        existing = [p for p in targets.values() if os.path.exists(p)]
        if existing:
            raise FileExistsError(f"refusing to overwrite {existing}; pass --force")

    window_sink = CsvSink(targets["windows"], KEY_COLUMNS + FEATURE_NAMES)
    flow_sink = CsvSink(targets["flows"], FLOW_KEY_COLUMNS + FLOW_FEATURE_NAMES) if write_flows else None
    try:
        stats = extract(paths, window_sink, flow_sink, on_file_done=on_file_done, should_stop=should_stop)
    finally:
        window_sink.close()
        if flow_sink is not None:
            flow_sink.close()

    summary = {
        "schema_version": SCHEMA_VERSION,
        "schema_fingerprint": schema_fingerprint(),
        "inputs": [
            {
                "path": path,
                "bytes": os.path.getsize(path),
                **({"sha256": (known_hashes or {}).get(path) or sha256_file(path)} if hash_inputs else {}),
            }
            for path in paths
        ],
        "windows_written": window_sink.rows,
        "flows_written": flow_sink.rows if flow_sink is not None else None,
        "counts": stats.as_dict(),
    }
    with open(targets["stats"], "w", encoding="utf-8", newline="\n") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return summary
