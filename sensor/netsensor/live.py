"""
Live, continuous DoS/DDoS monitoring.

Captures packets from a network interface, runs the SAME rolling-window feature extraction as the
offline pipeline (netsensor.pipeline.consume_raw), scores each closed window with the SAME trained
model, applies the SAME persistence rule, and forwards genuine alerts through the SAME backend
ingestion path — the only differences from offline replay are the packet SOURCE and that every alert
is labelled `dataOrigin: LIVE`.

The capture SOURCE is an injectable iterator of raw frames (CaptureSource), so the whole pipeline
(source -> windows -> model -> alert -> forward) is unit-testable WITHOUT Npcap; only the actual NIC
binding (ScapyCaptureSource) needs Npcap + scapy on the operator's machine.

Nothing here generates traffic. It only observes. It never isolates an endpoint or triggers any
response; it only records detections.
"""
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional

from .pipeline import consume_raw
from .flows import FlowTable, FragmentTable
from .stats import Stats
from .windows import WindowAggregator
from .schema import KEY_COLUMNS, FEATURE_NAMES

# A frame handed to the decoder: nanosecond timestamp, libpcap link type, raw link-layer bytes.
LINKTYPE_ETHERNET = 1


@dataclass
class RawFrame:
    ts_ns: int
    linktype: int
    data: bytes


class CaptureSource:
    """A source of raw frames. frames() yields RawFrame, or None as an idle 'tick' so the monitor can
    flush finished windows when traffic pauses. Implementations must make close() stop capture and
    release the handle."""

    def frames(self) -> Iterator[Optional[RawFrame]]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def describe(self) -> str:
        return "unknown source"


@dataclass
class MonitorLimits:
    max_seconds: float = 0.0          # 0 = unbounded (until stopped)
    max_packets: int = 0              # 0 = unbounded
    warmup_seconds: float = 5.0       # suppress alert FORWARDING for this long after start
    queue_size: int = 100_000         # bounded capture buffer; overflow is counted as packet loss


@dataclass
class MonitorStatus:
    interface: str = ""
    running: bool = False
    started_at: Optional[float] = None
    packets: int = 0
    bytes: int = 0
    windows_scored: int = 0
    over_threshold_windows: int = 0
    alerts: int = 0
    dropped_packets: int = 0
    last_inference_at: Optional[str] = None
    last_detection_at: Optional[str] = None
    model_version: str = ""
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        d = dict(self.__dict__)
        d["uptime_seconds"] = round(time.time() - self.started_at, 1) if self.started_at else 0.0
        return d


class LiveMonitor:
    """
    Drives one live monitoring session. Single-threaded consumption: the capture source pushes frames
    (e.g. from a scapy sniffer thread) and this monitor's run loop decodes, windows, scores and
    forwards. Thread-safe status snapshot via a lock.
    """

    def __init__(
        self,
        detector,
        organization_id: str,
        endpoint_id: str,
        forward_fn: Callable[[Dict[str, object]], None],
        limits: Optional[MonitorLimits] = None,
        on_status: Optional[Callable[[Dict[str, object]], None]] = None,
    ):
        self._detector = detector
        self._org = organization_id
        self._ep = endpoint_id
        self._forward = forward_fn
        self._limits = limits or MonitorLimits()
        self._on_status = on_status

        self._stats = Stats()
        self._fragments = FragmentTable(self._stats)
        self._flows = FlowTable(self._stats, None)
        self._windows = WindowAggregator(self._stats, self._on_window)
        from .ml.model import AlertTracker
        self._tracker = AlertTracker(detector.persistence)

        self._records = 0
        self._lock = threading.Lock()
        self._status = MonitorStatus(model_version=getattr(detector, "model_version", ""))
        self._stop = threading.Event()
        self._warmup_until = 0.0

    # --- window callback: score, persistence, forward (the live equivalent of predict's loop) ---
    def _on_window(self, row: Dict[str, object]) -> None:
        # Schema guard: a window row must carry exactly the dos-window-v1 key+feature columns.
        result = self._detector.score_window(row)
        state = self._tracker.observe(row["dst_ip"], int(row["window_start_ns"]), result["over_threshold"])
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._status.windows_scored += 1
            self._status.over_threshold_windows += int(result["over_threshold"])
            self._status.last_inference_at = now_iso
        if not state["raised"]:
            return
        # Suppress forwarding during warmup so startup transients never become an alert.
        if time.time() < self._warmup_until:
            return
        from .ml.alerts import detection_payload
        payload = detection_payload(
            row, result, organization_id=self._org, endpoint_id=self._ep,
            data_origin="LIVE", persistence=self._detector.persistence,
            captures=[], persistence_hits=state["hits"],
        )
        try:
            self._forward(payload)
            with self._lock:
                self._status.alerts += 1
                self._status.last_detection_at = now_iso
        except Exception as exc:  # a forward failure must not kill monitoring
            with self._lock:
                self._status.error = f"forward failed: {exc}"

    def stop(self) -> None:
        self._stop.set()

    def _publish_status(self) -> None:
        if self._on_status:
            try:
                self._on_status(self._status.as_dict())
            except Exception:
                pass

    def run(self, source: CaptureSource) -> MonitorStatus:
        start = time.time()
        self._warmup_until = start + self._limits.warmup_seconds
        with self._lock:
            self._status.running = True
            self._status.started_at = start
            self._status.interface = source.describe()
        self._publish_status()
        last_status = start
        try:
            for frame in source.frames():
                if self._stop.is_set():
                    break
                now = time.time()
                if frame is None:
                    # Idle tick: flush any windows that are complete as of now.
                    self._windows.advance_to(int(now * 1_000_000_000))
                else:
                    self._records = consume_raw(iter([frame]), self._fragments, self._flows,
                                                self._windows, self._stats, records=self._records)
                    with self._lock:
                        self._status.packets += 1
                        self._status.bytes += len(frame.data)
                # Resource limits and periodic status.
                if self._limits.max_packets and self._status.packets >= self._limits.max_packets:
                    break
                if self._limits.max_seconds and (now - start) >= self._limits.max_seconds:
                    break
                if now - last_status >= 2.0:
                    self._status.dropped_packets = getattr(source, "dropped", 0)
                    self._publish_status()
                    last_status = now
        finally:
            self._windows.finish()
            self._flows.flush()
            source.close()
            with self._lock:
                self._status.running = False
                self._status.dropped_packets = getattr(source, "dropped", 0)
            self._publish_status()
        return self._status

    def status(self) -> Dict[str, object]:
        with self._lock:
            return self._status.as_dict()


# ---------------------------------------------------------------------------
# scapy / Npcap capture source. Imported lazily so the rest of the module (and
# its tests) work without scapy installed.
# ---------------------------------------------------------------------------
SCAPY_HINT = (
    "Live capture needs scapy. Use the ml-service venv (it also has the model libs):\n"
    "  ..\\apps\\ml-service\\.venv\\Scripts\\python.exe -m pip install scapy\n"
    "and run `netsensor live` with that same python."
)

NPCAP_HINT = (
    "scapy is installed, but there is NO packet-capture provider (Npcap), so capture would see\n"
    "ZERO packets even though interfaces can be listed. Install Npcap and retry:\n"
    "  1. Download and install Npcap: https://npcap.com\n"
    "     During install, CHECK 'Install Npcap in WinPcap API-compatible Mode'.\n"
    "  2. Reopen PowerShell as Administrator (capture needs elevation).\n"
    "  3. Verify first with the capture smoke test (counts packets, sends nothing):\n"
    "       python -m netsensor live --smoke-test --interface \"<name>\" --seconds 5\n"
    "(Listing interfaces works WITHOUT Npcap and does NOT prove capture works.)"
)


def _require_scapy():
    try:
        import scapy.all as scapy  # noqa
        return scapy
    except Exception as exc:
        raise SystemExit(f"{SCAPY_HINT}\n(import error: {exc})")


def capture_provider_available(scapy=None) -> bool:
    """True only if scapy has a working L2 packet-capture backend (Npcap/libpcap) on this machine.
    Interface LISTING works without one, so this is checked separately before capturing."""
    scapy = scapy or _require_scapy()
    from scapy.config import conf
    return bool(getattr(conf, "use_pcap", False)) and conf.L2listen is not None


def _require_capture():
    """Return scapy only if packets can actually be captured; otherwise fail with Npcap instructions."""
    scapy = _require_scapy()
    if not capture_provider_available(scapy):
        raise SystemExit(NPCAP_HINT)
    return scapy


def list_interfaces() -> List[str]:
    scapy = _require_scapy()
    try:
        return list(scapy.get_if_list())
    except Exception as exc:
        raise SystemExit(f"could not list interfaces: {exc}\n{SCAPY_HINT}")


class ScapyCaptureSource(CaptureSource):
    """Live capture from a NIC via scapy's AsyncSniffer (Npcap). A bounded queue decouples the sniffer
    thread from the monitor; on overflow, frames are dropped and counted (never unbounded memory)."""

    def __init__(self, interface: str, linktype: int = LINKTYPE_ETHERNET, queue_size: int = 100_000, bpf: Optional[str] = None):
        # Fail fast if there is no real capture backend, instead of silently capturing zero packets.
        self._scapy = _require_capture()
        self._interface = interface
        self._linktype = linktype
        self._bpf = bpf
        self._q: "queue.Queue[RawFrame]" = queue.Queue(maxsize=queue_size)
        self._sniffer = None
        self.dropped = 0

    def _on_packet(self, pkt) -> None:
        try:
            frame = RawFrame(ts_ns=int(float(pkt.time) * 1_000_000_000), linktype=self._linktype, data=bytes(pkt))
            self._q.put_nowait(frame)
        except queue.Full:
            self.dropped += 1
        except Exception:
            self.dropped += 1

    def frames(self) -> Iterator[Optional[RawFrame]]:
        self._sniffer = self._scapy.AsyncSniffer(iface=self._interface, prn=self._on_packet,
                                                 store=False, filter=self._bpf)
        self._sniffer.start()
        while True:
            try:
                yield self._q.get(timeout=0.5)
            except queue.Empty:
                yield None  # idle tick

    def close(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def describe(self) -> str:
        return self._interface


def capture_smoke_test(interface: str, seconds: float = 5.0, linktype: int = LINKTYPE_ETHERNET,
                       queue_size: int = 100_000) -> Dict[str, object]:
    """
    Bounded read-only check that the capture PATH works: open the interface, count packets/bytes for
    `seconds`, then close cleanly. Runs NO model inference, forwards NOTHING, generates NO traffic.
    Fails fast with Npcap instructions if there is no capture provider. Use this to confirm real
    packets are being captured before starting live detection.
    """
    source = ScapyCaptureSource(interface, linktype=linktype, queue_size=queue_size)
    packets = 0
    total_bytes = 0
    start = time.time()
    try:
        for frame in source.frames():
            if time.time() - start >= seconds:
                break
            if frame is not None:
                packets += 1
                total_bytes += len(frame.data)
    finally:
        source.close()
    return {
        "interface": interface,
        "seconds": round(time.time() - start, 1),
        "packets": packets,
        "bytes": total_bytes,
        "dropped": getattr(source, "dropped", 0),
        "capturing": packets > 0,
    }


# The schema the window rows must match; exposed so a test can assert compatibility.
WINDOW_ROW_COLUMNS = KEY_COLUMNS + FEATURE_NAMES
