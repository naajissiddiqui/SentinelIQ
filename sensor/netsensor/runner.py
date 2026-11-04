"""
Resource-conscious job runner for continuous multi-file extraction.

    python -m netsensor run-jobs --jobs jobs.json [--dry-run] [--only JOB_ID]

A job is ONE continuous extraction over an ordered list of captures, so flow
state and baseline history carry across file boundaries (pipeline.extract).
A job file lists bounded jobs; run them a few at a time.

    {
      "job_file_version": "d0311-v1",
      "output_root": "C:/datasets/netsensor-runs/d0311",
      "write_flows": true,
      "limits": {"min_available_mb": 1500, "max_process_mb": 3000,
                 "min_free_disk_gb": 20, "low_priority": true},
      "jobs": [
        {"id": "g1", "inputs": {"dir": "C:/PCAP-03-11", "prefix": "SAT-03-11-2018_0", "first": 0, "last": 10}},
        {"id": "g2", "inputs": ["C:/PCAP-03-11/SAT-03-11-2018_011", "..."]}
      ]
    }

Guarantees:
  - Inputs are hashed and their order recorded before extraction starts.
  - Work happens in `<root>/<id>.attempt-<n>/`. Only a finished extraction is
    renamed to `<root>/<id>/`; nothing is ever overwritten or deleted.
  - A completed job is skipped after its outputs re-verify against the
    hashes in its `job.json`. A completed directory that fails verification
    stops the run: something changed it, and a person must look.
  - Aborted or failed attempts stay where they are, with `job.json` saying
    why and no `stats.json`, so `build-dataset` refuses them.
  - The extraction stops cleanly when available system memory falls below
    `min_available_mb`, the process exceeds `max_process_mb`, or a file named
    STOP appears in the output root.

Capture naming: tcpdump -C rotation names files PREFIX, PREFIX1, PREFIX2, ...,
so "SAT-03-11-2018_0" + "10" is file 10. Order is numeric, never lexicographic.
"""

import ctypes
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from .pipeline import ExtractionAborted, extract_to_dir, sha256_file

JOB_RECORD = "job.json"
PROGRESS = "progress.jsonl"
OUTPUTS = ("windows.csv", "flows.csv", "stats.json")

# Measured on CIC-DDoS2019 03-11 (single-source UDP flood, 2026-10-18): about
# 287 bytes per record, ~25k records/s in steady state at 2.6 GHz, flows.csv
# up to 0.45 x the input size, working set ~1.2 GB with ~0.9M live flows.
BYTES_PER_RECORD = 287
RECORDS_PER_SECOND = 25_000
OUTPUT_RATIO_WITH_FLOWS = 0.5
OUTPUT_RATIO_WINDOWS_ONLY = 0.05
REFERENCE_PEAK_MB = 1200


class JobError(RuntimeError):
    """The job file or the state on disk does not allow running."""


# --- capture ordering ---------------------------------------------------------

def capture_range(directory: str, prefix: str, first: int, last: int) -> List[str]:
    """Paths of rotated captures first..last, in numeric order. All must exist."""
    if first < 0 or last < first:
        raise JobError(f"bad capture range {first}..{last}")
    paths = []
    for i in range(first, last + 1):
        path = os.path.join(directory, prefix + ("" if i == 0 else str(i)))
        if not os.path.isfile(path):
            raise JobError(f"capture {path} does not exist")
        paths.append(path)
    return paths


def resolve_inputs(spec: object, where: str) -> List[str]:
    if isinstance(spec, list):
        paths = [str(p) for p in spec]
        for p in paths:
            if not os.path.isfile(p):
                raise JobError(f"{where}: capture {p} does not exist")
    elif isinstance(spec, dict):
        try:
            paths = capture_range(spec["dir"], spec["prefix"], int(spec["first"]), int(spec["last"]))
        except KeyError as missing:
            raise JobError(f"{where}: inputs needs {missing}") from None
    else:
        raise JobError(f"{where}: inputs must be a list of paths or a range")
    if not paths:
        raise JobError(f"{where}: no inputs")
    if len(set(os.path.abspath(p) for p in paths)) != len(paths):
        raise JobError(f"{where}: a capture is listed twice")
    return paths


# --- resource probes ------------------------------------------------------------

class _MemoryStatus(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


class _ProcessMemory(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def available_memory_mb() -> Optional[float]:
    if os.name == "nt":
        status = _MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return status.ullAvailPhys / 2**20
        return None
    try:
        with open("/proc/meminfo") as stream:
            for line in stream:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return None


def process_memory_mb() -> Tuple[Optional[float], Optional[float]]:
    """(current, peak) working set of this process."""
    if os.name == "nt":
        k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessMemory), ctypes.c_ulong]
        pmc = _ProcessMemory()
        pmc.cb = ctypes.sizeof(pmc)
        if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
            return pmc.WorkingSetSize / 2**20, pmc.PeakWorkingSetSize / 2**20
        return None, None
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        return None, peak
    except ImportError:
        return None, None


def free_disk_gb(path: str) -> float:
    probe = path
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    import shutil
    return shutil.disk_usage(probe).free / 2**30


def set_low_priority() -> None:
    if os.name == "nt":
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.SetPriorityClass(ctypes.c_void_p(k32.GetCurrentProcess()), 0x4000)  # BELOW_NORMAL
    else:
        os.nice(5)


# --- job file -------------------------------------------------------------------

DEFAULT_LIMITS = {"min_available_mb": 1500, "max_process_mb": 3000, "min_free_disk_gb": 20, "low_priority": True}


def load_job_file(path: str) -> Dict[str, object]:
    with open(path, encoding="utf-8") as stream:
        doc = json.load(stream)
    for key in ("job_file_version", "output_root", "jobs"):
        if key not in doc:
            raise JobError(f"job file is missing {key}")
    doc["limits"] = dict(DEFAULT_LIMITS, **doc.get("limits", {}))
    ids = [j.get("id") for j in doc["jobs"]]
    if not ids or any(not i or os.sep in str(i) or "/" in str(i) for i in ids) or len(set(ids)) != len(ids):
        raise JobError("every job needs a unique id without path separators")
    seen: Dict[str, str] = {}
    for job in doc["jobs"]:
        job["paths"] = resolve_inputs(job.get("inputs"), f"job {job['id']!r}")
        for p in job["paths"]:
            owner = seen.setdefault(os.path.abspath(p), job["id"])
            if owner != job["id"]:
                raise JobError(f"capture {p} is in jobs {owner!r} and {job['id']!r}")
    return doc


def estimate(paths: List[str], write_flows: bool) -> Dict[str, float]:
    size = sum(os.path.getsize(p) for p in paths)
    records = size / BYTES_PER_RECORD
    return {
        "input_gb": round(size / 2**30, 3),
        "records_estimate": int(records),
        "cpu_minutes_estimate": round(records / RECORDS_PER_SECOND / 60, 1),
        "output_gb_estimate": round(size * (OUTPUT_RATIO_WITH_FLOWS if write_flows else OUTPUT_RATIO_WINDOWS_ONLY) / 2**30, 3),
        "reference_peak_mb": REFERENCE_PEAK_MB,
    }


# --- verification ---------------------------------------------------------------

def _read_record(directory: str) -> Optional[Dict[str, object]]:
    path = os.path.join(directory, JOB_RECORD)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def verify_completed(directory: str, paths: List[str]) -> Tuple[bool, str]:
    record = _read_record(directory)
    if record is None:
        return False, "no job.json"
    if record.get("status") != "complete":
        return False, f"status is {record.get('status')!r}"
    expected = [{"path": os.path.abspath(p), "bytes": os.path.getsize(p)} for p in paths]
    recorded = [{"path": i["path"], "bytes": i["bytes"]} for i in record.get("inputs", [])]
    if recorded != expected:
        return False, "the job's inputs (paths, order or sizes) differ from the job file"
    for name, digest in record.get("outputs", {}).items():
        path = os.path.join(directory, name)
        if not os.path.exists(path) or sha256_file(path) != digest:
            return False, f"{name} does not match its recorded SHA-256"
    return True, "verified"


# --- running --------------------------------------------------------------------

class _Guard:
    """should_stop() for the pipeline: memory limits and the STOP file, checked at most once a second."""

    def __init__(self, limits: Dict[str, object], stop_file: str,
                 available: Callable[[], Optional[float]], process: Callable[[], Tuple[Optional[float], Optional[float]]]):
        self.limits, self.stop_file = limits, stop_file
        self.available, self.process = available, process
        self._last = 0.0

    def __call__(self) -> Optional[str]:
        now = time.monotonic()
        if now - self._last < 1.0:
            return None
        self._last = now
        if os.path.exists(self.stop_file):
            return "STOP file present"
        avail = self.available()
        if avail is not None and avail < self.limits["min_available_mb"]:
            return f"system available memory {avail:.0f} MB < {self.limits['min_available_mb']} MB"
        current, _ = self.process()
        if current is not None and current > self.limits["max_process_mb"]:
            return f"process working set {current:.0f} MB > {self.limits['max_process_mb']} MB"
        return None


def _write_json(path: str, doc: Dict[str, object]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(doc, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(tmp, path)


def _next_attempt(root: str, job_id: str) -> str:
    n = 1
    while os.path.exists(os.path.join(root, f"{job_id}.attempt-{n}")):
        n += 1
    return os.path.join(root, f"{job_id}.attempt-{n}")


def preflight(doc: Dict[str, object], available=available_memory_mb) -> List[str]:
    """Problems that must stop a run before anything is written."""
    problems = []
    limits = doc["limits"]
    total = estimate([p for j in doc["jobs"] for p in j["paths"]], doc.get("write_flows", True))
    disk = free_disk_gb(doc["output_root"])
    if disk - total["output_gb_estimate"] < limits["min_free_disk_gb"]:
        problems.append(f"free disk {disk:.1f} GB minus estimated output {total['output_gb_estimate']} GB "
                        f"is below {limits['min_free_disk_gb']} GB")
    avail = available()
    if avail is not None and avail < limits["min_available_mb"] + 300:
        problems.append(f"available memory {avail:.0f} MB is too close to the {limits['min_available_mb']} MB stop limit")
    return problems


def run_job(job: Dict[str, object], doc: Dict[str, object], log: Callable[[str], None],
            available=available_memory_mb, process=process_memory_mb) -> Dict[str, object]:
    root = doc["output_root"]
    final = os.path.join(root, job["id"])
    paths = job["paths"]
    if os.path.exists(final):
        ok, why = verify_completed(final, paths)
        if ok:
            log(f"[{job['id']}] skipped: completed output verified")
            return {"id": job["id"], "status": "skipped-verified"}
        raise JobError(f"[{job['id']}] {final} exists but does not verify ({why}); not touching it")

    attempt = _next_attempt(root, job["id"])
    os.makedirs(attempt)
    record: Dict[str, object] = {
        "job_id": job["id"], "job_file_version": doc["job_file_version"], "status": "running",
        "attempt_dir": os.path.abspath(attempt), "write_flows": doc.get("write_flows", True),
        "limits": doc["limits"], "estimate": estimate(paths, doc.get("write_flows", True)),
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inputs": [],
    }
    _write_json(os.path.join(attempt, JOB_RECORD), record)
    log(f"[{job['id']}] hashing {len(paths)} inputs")
    hashes = {}
    for p in paths:
        hashes[p] = sha256_file(p)
        record["inputs"].append({"path": os.path.abspath(p), "bytes": os.path.getsize(p), "sha256": hashes[p]})
    _write_json(os.path.join(attempt, JOB_RECORD), record)

    t0 = time.perf_counter()
    marks = {"t": t0, "records": 0, "decoded": 0}
    progress = open(os.path.join(attempt, PROGRESS), "a", encoding="utf-8")

    def on_file_done(index, path, stats, live_flows):
        now = time.perf_counter()
        counts = stats.as_dict()
        current, peak = process()
        entry = {
            "file_index": index, "path": os.path.abspath(path), "wall_s": round(now - marks["t"], 3),
            "records": counts.get("records_read", 0) - marks["records"],
            "decoded": counts.get("packets_decoded", 0) - marks["decoded"],
            "truncated": counts.get("truncated_record", 0) + counts.get("truncated_block", 0),
            "live_flows": live_flows, "working_set_mb": current, "peak_working_set_mb": peak,
            "available_mb": available(), "elapsed_s": round(now - t0, 2),
        }
        marks.update(t=now, records=counts.get("records_read", 0), decoded=counts.get("packets_decoded", 0))
        progress.write(json.dumps(entry, sort_keys=True) + "\n")
        progress.flush()
        log(f"[{job['id']}] file {index + 1}/{len(paths)} {os.path.basename(path)}: "
            f"{entry['records']} records in {entry['wall_s']} s, live flows {live_flows}")

    guard = _Guard(doc["limits"], os.path.join(root, "STOP"), available, process)
    try:
        summary = extract_to_dir(paths, attempt, write_flows=doc.get("write_flows", True),
                                 on_file_done=on_file_done, should_stop=guard, known_hashes=hashes)
    except ExtractionAborted as reason:
        record.update(status="aborted", error=str(reason))
    except Exception as error:  # a damaged capture, a full disk: recorded in job.json, run stops
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        progress.close()
    current, peak = process()
    record.update(wall_s=round(time.perf_counter() - t0, 2), peak_working_set_mb=peak,
                  ended_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    if record["status"] != "running":
        _write_json(os.path.join(attempt, JOB_RECORD), record)
        log(f"[{job['id']}] {record['status']}: {record['error']} (attempt kept at {attempt})")
        return {"id": job["id"], "status": record["status"], "error": record["error"], "attempt": attempt}

    record.update(status="complete", windows_written=summary["windows_written"],
                  flows_written=summary["flows_written"], counts=summary["counts"],
                  outputs={n: sha256_file(os.path.join(attempt, n)) for n in OUTPUTS
                           if os.path.exists(os.path.join(attempt, n))})
    _write_json(os.path.join(attempt, JOB_RECORD), record)
    os.rename(attempt, final)  # fails rather than replacing if `final` appeared meanwhile
    log(f"[{job['id']}] complete: {summary['windows_written']} windows in {record['wall_s']} s -> {final}")
    return {"id": job["id"], "status": "complete", "dir": final}


def run_jobs(job_file: str, dry_run: bool = False, only: Optional[List[str]] = None,
             log: Callable[[str], None] = print, available=available_memory_mb,
             process=process_memory_mb) -> List[Dict[str, object]]:
    doc = load_job_file(job_file)
    jobs = [j for j in doc["jobs"] if not only or j["id"] in only]
    if only and len(jobs) != len(set(only)):
        raise JobError(f"unknown job id in {only}")
    doc["jobs"] = jobs
    for job in jobs:
        est = estimate(job["paths"], doc.get("write_flows", True))
        state = "pending"
        final = os.path.join(doc["output_root"], job["id"])
        if os.path.exists(final):
            ok, why = verify_completed(final, job["paths"])
            state = "complete (verified)" if ok else f"EXISTS BUT UNVERIFIED: {why}"
        log(f"[{job['id']}] {len(job['paths'])} files {os.path.basename(job['paths'][0])} .. "
            f"{os.path.basename(job['paths'][-1])}; {est}; {state}")
    problems = preflight(doc, available)
    for p in problems:
        log(f"preflight: {p}")
    if dry_run:
        log("dry run: nothing written")
        return [{"id": j["id"], "status": "dry-run"} for j in jobs]
    if problems:
        raise JobError("preflight failed: " + "; ".join(problems))
    if doc["limits"].get("low_priority"):
        set_low_priority()
    os.makedirs(doc["output_root"], exist_ok=True)
    results = []
    for job in jobs:
        result = run_job(job, doc, log, available, process)
        results.append(result)
        if result["status"] in ("aborted", "failed"):
            log("stopping: later jobs need the resources this one ran out of, or a person to look")
            break
    return results
