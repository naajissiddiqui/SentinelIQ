import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from netsensor import pipeline
from netsensor.pipeline import ExtractionAborted, extract, extract_to_dir
from netsensor.runner import JobError, capture_range, run_jobs
from netsensor.schema import format_value
from tests import pcap_builder as pb
from tests.test_pipeline import benign_capture

T0 = 1_700_000_000 * pb.S


def plenty():
    return 64_000.0


def process():
    return 100.0, 120.0


class Quiet:
    def __init__(self):
        self.lines = []

    def __call__(self, line):
        self.lines.append(line)


class ContinuousExtractionTest(unittest.TestCase):
    """A capture split across files must give exactly what the whole capture gives."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        frames = sorted(benign_capture(T0), key=lambda f: f[0])
        half = len(frames) // 2
        self.whole = self._pcap("whole.pcap", frames)
        self.parts = [self._pcap("a.pcap", frames[:half]), self._pcap("b.pcap", frames[half:])]

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _pcap(self, name, frames):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as stream:
            stream.write(pb.pcap_bytes(frames))
        return path

    def _run(self, paths, **hooks):
        windows, flows = [], []
        stats = extract(paths, windows.append, flows.append, **hooks)
        text = lambda rows: [{k: format_value(v) for k, v in r.items()} for r in rows]
        return text(windows), text(flows), stats

    def test_flow_state_and_baseline_carry_across_file_boundaries(self):
        w_whole, f_whole, _ = self._run([self.whole])
        w_parts, f_parts, stats = self._run(self.parts)
        self.assertEqual(w_parts, w_whole)
        self.assertEqual(f_parts, f_whole)
        self.assertEqual(stats.get("files_read"), 2)

    def test_hooks_do_not_change_outputs(self):
        a = os.path.join(self.tmp, "plain")
        b = os.path.join(self.tmp, "hooked")
        extract_to_dir(self.parts, a)
        seen = []
        extract_to_dir(self.parts, b, on_file_done=lambda i, p, s, n: seen.append((i, n)),
                       should_stop=lambda: None)
        for name in ("windows.csv", "flows.csv", "stats.json"):
            with open(os.path.join(a, name), "rb") as x, open(os.path.join(b, name), "rb") as y:
                self.assertEqual(x.read(), y.read(), name)
        self.assertEqual([i for i, _ in seen], [0, 1])

    def test_stop_request_aborts_without_a_stats_file(self):
        out = os.path.join(self.tmp, "stopped")
        with mock.patch.object(pipeline, "STOP_CHECK_EVERY", 1):
            with self.assertRaisesRegex(ExtractionAborted, "memory"):
                extract_to_dir(self.parts, out, should_stop=lambda: "memory pressure")
        self.assertFalse(os.path.exists(os.path.join(out, "stats.json")))


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.caps = os.path.join(self.tmp, "caps")
        os.makedirs(self.caps)
        frames = sorted(benign_capture(T0), key=lambda f: f[0])
        third = len(frames) // 3
        # tcpdump -C names: cap_0, cap_01, cap_02 ... (prefix "cap_0" + index)
        for i, chunk in enumerate((frames[:third], frames[third:2 * third], frames[2 * third:])):
            with open(os.path.join(self.caps, "cap_0" + ("" if i == 0 else str(i))), "wb") as stream:
                stream.write(pb.pcap_bytes(chunk))
        self.root = os.path.join(self.tmp, "runs")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def job_file(self, jobs, **extra):
        doc = {"job_file_version": "test", "output_root": self.root, "write_flows": True,
               "limits": {"min_available_mb": 100, "max_process_mb": 10_000, "min_free_disk_gb": 0,
                          "low_priority": False},
               "jobs": jobs}
        doc.update(extra)
        path = os.path.join(self.tmp, "jobs.json")
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(doc, stream)
        return path

    def range_job(self, job_id="g1", first=0, last=2):
        return {"id": job_id, "inputs": {"dir": self.caps, "prefix": "cap_0", "first": first, "last": last}}

    def go(self, path, **kw):
        kw.setdefault("available", plenty)
        kw.setdefault("process", process)
        return run_jobs(path, log=Quiet(), **kw)

    def test_numeric_capture_order(self):
        for i in range(3, 12):
            open(os.path.join(self.caps, f"cap_0{i}"), "wb").close()
        names = [os.path.basename(p) for p in capture_range(self.caps, "cap_0", 8, 11)]
        self.assertEqual(names, ["cap_08", "cap_09", "cap_010", "cap_011"])
        with self.assertRaisesRegex(JobError, "does not exist"):
            capture_range(self.caps, "cap_0", 0, 20)

    def test_complete_then_skip_and_detect_tampering(self):
        jobs = self.job_file([self.range_job()])
        result = self.go(jobs)
        self.assertEqual(result[0]["status"], "complete")
        final = os.path.join(self.root, "g1")
        with open(os.path.join(final, "job.json"), encoding="utf-8") as stream:
            record = json.load(stream)
        self.assertEqual(record["status"], "complete")
        self.assertEqual([os.path.basename(i["path"]) for i in record["inputs"]], ["cap_0", "cap_01", "cap_02"])
        self.assertEqual(len(record["inputs"][0]["sha256"]), 64)
        with open(os.path.join(final, "progress.jsonl"), encoding="utf-8") as stream:
            self.assertEqual(len(stream.readlines()), 3)
        with open(os.path.join(final, "stats.json"), encoding="utf-8") as stream:
            self.assertEqual(json.load(stream)["inputs"][1]["sha256"], record["inputs"][1]["sha256"])

        self.assertEqual(self.go(jobs)[0]["status"], "skipped-verified")
        with open(os.path.join(final, "windows.csv"), "a", encoding="utf-8") as stream:
            stream.write("tampered\n")
        with self.assertRaisesRegex(JobError, "does not verify"):
            self.go(jobs)

    def test_runner_output_equals_direct_continuous_extraction(self):
        self.go(self.job_file([self.range_job()]))
        direct = os.path.join(self.tmp, "direct")
        extract_to_dir(capture_range(self.caps, "cap_0", 0, 2), direct)
        for name in ("windows.csv", "flows.csv"):
            with open(os.path.join(direct, name), "rb") as x, open(os.path.join(self.root, "g1", name), "rb") as y:
                self.assertEqual(x.read(), y.read(), name)

    def test_malformed_capture_fails_the_job_and_keeps_the_attempt(self):
        with open(os.path.join(self.caps, "cap_01"), "wb") as stream:
            stream.write(b"not a capture at all")
        jobs = self.job_file([self.range_job(), {"id": "g2", "inputs": [os.path.join(self.tmp, "jobs.json")]}])
        # g2 never runs: the run stops at the first failed job.
        result = self.go(jobs)
        self.assertEqual([r["status"] for r in result], ["failed"])
        self.assertIn("PcapFormatError", result[0]["error"])
        self.assertFalse(os.path.exists(os.path.join(self.root, "g1")))
        attempt = os.path.join(self.root, "g1.attempt-1")
        self.assertFalse(os.path.exists(os.path.join(attempt, "stats.json")))
        with open(os.path.join(attempt, "job.json"), encoding="utf-8") as stream:
            self.assertEqual(json.load(stream)["status"], "failed")

    def test_memory_pressure_aborts_cleanly_and_a_retry_uses_a_new_attempt(self):
        jobs = self.job_file([self.range_job()])
        calls = {"n": 0}

        def falling():
            calls["n"] += 1
            return 64_000.0 if calls["n"] <= 1 else 50.0  # preflight passes, then memory runs out

        with mock.patch.object(pipeline, "STOP_CHECK_EVERY", 1):
            result = self.go(jobs, available=falling)
        self.assertEqual(result[0]["status"], "aborted")
        self.assertIn("available memory", result[0]["error"])
        self.assertTrue(os.path.isdir(os.path.join(self.root, "g1.attempt-1")))
        self.assertEqual(self.go(jobs)[0]["status"], "complete")
        self.assertTrue(os.path.isdir(os.path.join(self.root, "g1.attempt-1")))  # kept, not reused
        self.assertTrue(os.path.isdir(os.path.join(self.root, "g1")))

    def test_stop_file_aborts(self):
        os.makedirs(self.root)
        open(os.path.join(self.root, "STOP"), "w").close()
        with mock.patch.object(pipeline, "STOP_CHECK_EVERY", 1):
            result = self.go(self.job_file([self.range_job()]))
        self.assertEqual(result[0]["status"], "aborted")
        self.assertIn("STOP", result[0]["error"])

    def test_dry_run_and_failed_preflight_write_nothing(self):
        jobs = self.job_file([self.range_job()])
        self.assertEqual(self.go(jobs, dry_run=True)[0]["status"], "dry-run")
        self.assertFalse(os.path.exists(self.root))
        with self.assertRaisesRegex(JobError, "preflight"):
            self.go(jobs, available=lambda: 150.0)
        self.assertFalse(os.path.exists(self.root))

    def test_a_capture_may_belong_to_one_job_only(self):
        jobs = self.job_file([self.range_job("g1", 0, 1), self.range_job("g2", 1, 2)])
        with self.assertRaisesRegex(JobError, "in jobs"):
            self.go(jobs)


if __name__ == "__main__":
    unittest.main()
