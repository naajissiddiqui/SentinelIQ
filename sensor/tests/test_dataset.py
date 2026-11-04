import csv
import json
import os
import shutil
import tempfile
import unittest

from netsensor.__main__ import main
from netsensor.dataset import PURGED, DatasetError, build_dataset
from netsensor.labels import parse_rules
from netsensor.pipeline import extract_to_dir
from netsensor.schema import FEATURE_NAMES, KEY_COLUMNS, WINDOW_NS
from tests import pcap_builder as pb
from tests.test_labels import iso, rules_doc
from tests.test_pipeline import _write, benign_capture

T0 = 1_700_000_000 * pb.S
T1 = T0 + 3600 * pb.S


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as stream:
        return list(csv.reader(stream))


class DatasetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sources = {}
        for name, t0 in (("early", T0), ("late", T1)):
            pcap = _write(pb.pcap_bytes(benign_capture(t0)))
            self.addCleanup(os.unlink, pcap)
            out = os.path.join(self.tmp, name)
            extract_to_dir([pcap], out)
            self.sources[name] = out

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def plan(self, sources, purge=180, name="plan.json"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as stream:
            json.dump({"plan_version": "test", "purge_seconds": purge, "sources": sources}, stream)
        return path

    def test_builds_aligned_files_without_labels(self):
        plan = self.plan([{"id": "e", "dir": self.sources["early"], "split": "train"},
                          {"id": "l", "dir": self.sources["late"], "split": "test"}])
        out = os.path.join(self.tmp, "ds")
        manifest = build_dataset(plan, out)

        features = read_csv(os.path.join(out, "features.csv"))
        labels = read_csv(os.path.join(out, "labels.csv"))
        splits = read_csv(os.path.join(out, "splits.csv"))
        self.assertEqual(features[0], ["source_id"] + KEY_COLUMNS + FEATURE_NAMES)
        self.assertNotIn("label", features[0])
        self.assertEqual(len(features), len(labels))
        self.assertEqual(len(features), len(splits))
        for f, l, s in zip(features[1:], labels[1:], splits[1:]):
            key = [f[0], f[2], f[4]]  # source_id, window_start_ns, dst_ip
            self.assertEqual(l[:3], key)
            self.assertEqual(s[:3], key)
            self.assertEqual(l[3], "unlabelled")
            self.assertEqual(s[3], "train" if f[0] == "e" else "test")

        early_rows = read_csv(os.path.join(self.sources["early"], "windows.csv"))
        self.assertEqual([r[1:] for r in features[1:len(early_rows)]], early_rows[1:])
        self.assertFalse(manifest["usable_for_training"])
        self.assertFalse(manifest["labels"]["applied"])
        self.assertEqual(manifest["rows_total"], len(features) - 1)
        self.assertEqual(len(manifest["sources"][0]["captures"][0]["sha256"]), 64)
        self.assertEqual(sorted(os.listdir(out)), ["features.csv", "labels.csv", "manifest.json", "splits.csv"])

    def test_output_is_reproducible_and_never_overwritten(self):
        plan = self.plan([{"id": "e", "dir": self.sources["early"], "split": "train"}])
        a, b = os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b")
        build_dataset(plan, a)
        build_dataset(plan, b)
        for name in ("features.csv", "labels.csv", "splits.csv", "manifest.json"):
            with open(os.path.join(a, name), "rb") as x, open(os.path.join(b, name), "rb") as y:
                self.assertEqual(x.read(), y.read(), name)
        with self.assertRaises(FileExistsError):
            build_dataset(plan, a)

    def test_a_capture_may_not_appear_in_two_sources(self):
        plan = self.plan([{"id": "x", "dir": self.sources["early"], "split": "train"},
                          {"id": "y", "dir": self.sources["early"], "split": "test"}])
        with self.assertRaisesRegex(DatasetError, "one source only"):
            build_dataset(plan, os.path.join(self.tmp, "ds"))

    def test_time_blocks_purge_rows_near_a_split_change(self):
        cut = T0 + 30 * pb.S
        plan = self.plan([{"id": "e", "dir": self.sources["early"], "blocks": [
            {"from": iso(T0 - 600 * pb.S), "to": iso(cut), "split": "train"},
            {"from": iso(cut), "to": iso(T0 + 600 * pb.S), "split": "validation"}]}], purge=10)
        out = os.path.join(self.tmp, "ds")
        build_dataset(plan, out)
        seen = set()
        for _, start, _, split in read_csv(os.path.join(out, "splits.csv"))[1:]:
            start = int(start)
            near = start < cut + 10 * pb.S and start + WINDOW_NS > cut - 10 * pb.S
            expected = PURGED if near else ("train" if start < cut else "validation")
            self.assertEqual(split, expected, start - T0)
            seen.add(split)
        self.assertEqual(seen, {"train", "validation", PURGED})

    def test_warmup_rows_are_marked_and_recorded(self):
        path = os.path.join(self.tmp, "warm.json")
        with open(path, "w", encoding="utf-8") as stream:
            json.dump({"plan_version": "t", "purge_seconds": 0, "warmup_seconds": 30,
                       "sources": [{"id": "e", "dir": self.sources["early"], "split": "train"}]}, stream)
        out = os.path.join(self.tmp, "ds")
        manifest = build_dataset(path, out)
        rows = read_csv(os.path.join(out, "splits.csv"))[1:]
        first = min(int(r[1]) for r in rows)
        for _, start, _, split in rows:
            self.assertEqual(split, "warmup" if int(start) < first + 30 * pb.S else "train")
        self.assertIn("warmup", {r[3] for r in rows})
        self.assertEqual(manifest["plan"]["warmup_seconds"], 30)

    def test_labels_come_from_rules_and_mark_the_dataset_trusted(self):
        rules = parse_rules(rules_doc([{"id": "u", "family": "UDP", "start": iso(T0 + 10 * pb.S),
                                        "end": iso(T0 + 45 * pb.S), "victims": [pb.SERVER]}], guard=5))
        plan = self.plan([{"id": "e", "dir": self.sources["early"], "split": "train"}])
        out = os.path.join(self.tmp, "ds")
        manifest = build_dataset(plan, out, rules)
        labels = {(r[1], r[2]): r[3] for r in read_csv(os.path.join(out, "labels.csv"))[1:]}
        server_attack = [k for k, v in labels.items() if k[1] == pb.SERVER and v == "attack"]
        self.assertTrue(server_attack)
        self.assertTrue(all(T0 + 15 * pb.S <= int(s) and int(s) + WINDOW_NS <= T0 + 40 * pb.S
                            for s, _ in server_attack))
        self.assertTrue(all(v == "benign" for (s, h), v in labels.items() if h != pb.SERVER))
        self.assertTrue(manifest["usable_for_training"])
        self.assertEqual(manifest["labels"]["sha256"], rules.sha256)

    def test_damaged_source_fails_without_leaving_files(self):
        broken = os.path.join(self.tmp, "broken")
        shutil.copytree(self.sources["late"], broken)
        rows = read_csv(os.path.join(broken, "windows.csv"))
        rows[-1][len(KEY_COLUMNS)] = "inf"
        with open(os.path.join(broken, "windows.csv"), "w", newline="", encoding="utf-8") as stream:
            csv.writer(stream, lineterminator="\n").writerows(rows)
        plan = self.plan([{"id": "e", "dir": self.sources["early"], "split": "train"},
                          {"id": "b", "dir": broken, "split": "test"}])
        out = os.path.join(self.tmp, "ds")
        with self.assertRaisesRegex(DatasetError, "infinite"):
            build_dataset(plan, out)
        self.assertEqual(os.listdir(out), [])

    def test_unfinished_extraction_is_refused(self):
        partial = os.path.join(self.tmp, "partial")
        shutil.copytree(self.sources["early"], partial)
        os.remove(os.path.join(partial, "stats.json"))
        plan = self.plan([{"id": "p", "dir": partial, "split": "train"}])
        with self.assertRaisesRegex(DatasetError, "did not finish"):
            build_dataset(plan, os.path.join(self.tmp, "ds"))

    def test_cli_refuses_unverified_labels_unless_allowed(self):
        plan = self.plan([{"id": "e", "dir": self.sources["early"], "split": "train"}])
        rules = os.path.join(self.tmp, "rules.json")
        with open(rules, "wb") as stream:
            stream.write(rules_doc(verified=False))
        self.assertEqual(main(["build-dataset", "--plan", plan, "--labels", rules,
                               "--out-dir", os.path.join(self.tmp, "x")]), 2)
        self.assertEqual(main(["build-dataset", "--plan", plan, "--labels", rules,
                               "--allow-unverified-labels", "--out-dir", os.path.join(self.tmp, "y")]), 0)
        with open(os.path.join(self.tmp, "y", "manifest.json"), encoding="utf-8") as stream:
            manifest = json.load(stream)
        self.assertFalse(manifest["usable_for_training"])
        self.assertFalse(manifest["labels"]["trusted"])


if __name__ == "__main__":
    unittest.main()
