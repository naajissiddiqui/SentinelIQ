"""
ML training/inference tests. All data here is SYNTHETIC (tests/synthetic_windows.py)
and tests software behaviour only. Needs numpy/xgboost/scikit-learn (ml-service venv);
skipped elsewhere.
"""

import csv
import importlib.util
import json
import math
import os
import random
import shutil
import tempfile
import unittest

HAVE_ML = all(importlib.util.find_spec(m) for m in ("numpy", "xgboost", "sklearn"))

if HAVE_ML:
    import numpy as np
    from netsensor import evaluate as ev
    from netsensor.dataset import build_dataset, sha256_file
    from netsensor.labels import load_rules
    from netsensor.ml import STATUS_HEURISTIC, STATUS_SYNTHETIC
    from netsensor.ml.alerts import detection_payload, risk_assessment, risk_score
    from netsensor.ml.cli import main as ml_main
    from netsensor.ml.data import DataError, load_dataset
    from netsensor.ml.features import FeatureError
    from netsensor.ml.model import AlertTracker, BundleError, DosDetector, PpsHeuristic
    from netsensor.ml.train import TrainingRefused, train
    from netsensor.schema import FEATURE_NAMES, KEY_COLUMNS, SCHEMA_VERSION, WINDOW_NS
    from tests.synthetic_windows import build_fixture

SMALL_GATES = {"gates": {"min_attack_windows": {"train": 100, "validation": 30, "test": 30},
                         "min_benign_windows": {"train": 500, "validation": 300, "test": 300}},
               "xgboost": {"n_estimators": 120}, "tuning_grid": {}}


@unittest.skipUnless(HAVE_ML, "numpy/xgboost/scikit-learn not installed (use the ml-service venv)")
class MlPipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        fx = build_fixture(os.path.join(cls.tmp, "fixture"))
        cls.dataset = os.path.join(cls.tmp, "dataset")
        build_dataset(fx["plan"], cls.dataset, load_rules(fx["rules"]))
        cls.bundle = os.path.join(cls.tmp, "bundle")
        cls.trained = train(cls.dataset, cls.bundle, SMALL_GATES)
        cls.detector = DosDetector.load(cls.bundle)
        cls.victim = fx["victim"]
        with open(os.path.join(cls.tmp, "fixture", "synthetic-test", "windows.csv"), newline="") as stream:
            cls.test_rows = list(csv.DictReader(stream))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def row(self, kind):
        """A test-split window: 'flood' (sustained, baseline ratio near 1), 'burst' or 'normal'."""
        for r in self.test_rows:
            if kind == "flood" and r["dst_ip"] == self.victim and float(r["in_pkts_per_s"]) > 5000 \
                    and r["in_pps_ratio_baseline"] != "nan" and float(r["in_pps_ratio_baseline"]) < 2:
                return dict(r)
            if kind == "burst" and r["dst_ip"] != self.victim and float(r["in_pkts_per_s"]) > 1500:
                return dict(r)
            if kind == "normal" and r["dst_ip"] != self.victim and float(r["in_pkts_per_s"]) < 10:
                return dict(r)
        self.fail(f"fixture has no {kind} window")

    # --- training discipline ---------------------------------------------------
    def test_bundle_is_marked_synthetic_and_complete(self):
        self.assertEqual(self.trained["status"], STATUS_SYNTHETIC)
        self.assertEqual(self.trained["feature_names"], FEATURE_NAMES)
        for name in ("model.json", "preprocessing.json", "bundle.json", "report.json", "report.md"):
            self.assertTrue(os.path.exists(os.path.join(self.bundle, name)), name)
        with open(os.path.join(self.bundle, "report.json")) as stream:
            report = json.load(stream)
        self.assertTrue(any("SYNTHETIC" in note for note in report["limitations"]))
        self.assertIn("model", report["splits"]["test"])
        self.assertIn("pps_baseline", report["splits"]["test"])

    def test_threshold_comes_from_validation_only(self):
        ds = load_dataset(self.dataset)
        va = ds.splits["validation"]
        scores = [self.detector.score_vector(list(x), FEATURE_NAMES)["score"] for x in va.x]
        expected = ev.threshold_for_fpr(scores, [bool(v) for v in va.y], self.trained["target_fpr"])
        self.assertAlmostEqual(self.trained["threshold"], expected, places=6)

    def test_preprocessing_fitted_on_train_only(self):
        ds = load_dataset(self.dataset)
        with open(os.path.join(self.bundle, "preprocessing.json")) as stream:
            stats = json.load(stream)["stats"]
        train_max = float(np.nanmax(ds.splits["train"].x[:, FEATURE_NAMES.index("in_pkts_per_s")]))
        self.assertEqual(stats["in_pkts_per_s"]["max"], train_max)

    def test_training_is_deterministic(self):
        again = os.path.join(self.tmp, "bundle-again")
        train(self.dataset, again, SMALL_GATES)
        self.assertEqual(sha256_file(os.path.join(again, "model.json")), sha256_file(os.path.join(self.bundle, "model.json")))
        other = DosDetector.load(again)
        row = self.row("flood")
        self.assertEqual(other.score_window(row)["score"], self.detector.score_window(row)["score"])

    def test_tuning_selects_on_validation_and_records_candidates(self):
        out = os.path.join(self.tmp, "tuned")
        cfg = dict(SMALL_GATES, tuning_grid={"max_depth": [2, 4]})
        bundle = train(self.dataset, out, cfg)
        cands = bundle["tuning"]["candidates"]
        self.assertEqual([c["params"]["max_depth"] for c in cands], [2, 4])
        best = max(cands, key=lambda c: (c["validation_pr_auc"], -c["trees"]))
        self.assertEqual(bundle["xgboost_params_used"]["max_depth"], best["params"]["max_depth"])
        with open(os.path.join(out, "report.json")) as stream:
            self.assertTrue(any("optimistic" in n for n in json.load(stream)["limitations"]))

    def test_bundle_is_never_overwritten(self):
        with self.assertRaises(FileExistsError):
            train(self.dataset, self.bundle, SMALL_GATES)

    # --- refusal gates -----------------------------------------------------------
    def test_default_gates_refuse_and_explain(self):
        out = os.path.join(self.tmp, "refused-gates")
        with self.assertRaises(TrainingRefused) as ctx:
            train(self.dataset, out, {"gates": {"min_attack_windows": {"test": 10_000}}})
        self.assertTrue(any("test:" in r and "attack windows" in r for r in ctx.exception.reasons))
        with open(os.path.join(out, "training_refused.json")) as stream:
            self.assertTrue(json.load(stream)["refused"])
        self.assertFalse(os.path.exists(os.path.join(out, "model.json")))

    def test_unverified_labels_and_missing_warmup_are_refused(self):
        for name, kwargs in (("unverified", {"verified": False}), ("no-warmup", {"warmup": 0})):
            with self.subTest(name):
                root = os.path.join(self.tmp, f"fx-{name}")
                fx = build_fixture(root, **kwargs)
                ds_dir = os.path.join(root, "ds")
                build_dataset(fx["plan"], ds_dir, load_rules(fx["rules"], allow_unverified=True))
                with self.assertRaises(TrainingRefused) as ctx:
                    train(ds_dir, os.path.join(root, "bundle"), SMALL_GATES)
                expected = "usable_for_training" if name == "unverified" else "warmup_seconds"
                self.assertTrue(any(expected in r for r in ctx.exception.reasons), ctx.exception.reasons)

    # --- robustness ------------------------------------------------------------------
    def test_sustained_flood_with_baseline_near_one_is_still_detected(self):
        row = self.row("flood")
        self.assertLess(float(row["in_pps_ratio_baseline"]), 2)
        self.assertTrue(self.detector.score_window(row)["over_threshold"])

    def test_legitimate_burst_and_normal_traffic_stay_below_threshold(self):
        for kind in ("burst", "normal"):
            with self.subTest(kind):
                self.assertFalse(self.detector.score_window(self.row(kind))["over_threshold"])

    def test_invalid_inputs_are_rejected(self):
        good = self.row("normal")
        cases = {
            "missing features": {k: v for k, v in good.items() if k != "in_bytes"},
            "unexpected fields": dict(good, label="attack"),
            "infinite": dict(good, in_bytes="inf"),
            "NaN in non-nullable": dict(good, in_packets="nan"),
            "schema_version": dict(good, schema_version="dos-window-v0"),
        }
        for message, row in cases.items():
            with self.subTest(message):
                with self.assertRaisesRegex(FeatureError, message):
                    self.detector.score_window(row)
        values = [float(good[n]) for n in FEATURE_NAMES]
        names = list(FEATURE_NAMES)
        names[0], names[1] = names[1], names[0]
        with self.assertRaisesRegex(FeatureError, "wrong order"):
            self.detector.score_vector(values, names)
        nullable = dict(good, in_pps_ratio_baseline="nan", tcp_rst_ratio="nan")
        self.assertIn("score", self.detector.score_window(nullable))

    def test_inference_is_deterministic_and_explained(self):
        row = self.row("flood")
        a, b = self.detector.score_window(row), self.detector.score_window(dict(row))
        self.assertEqual(a, b)
        self.assertEqual(len(a["top_features"]), 5)
        self.assertEqual(a["status"], STATUS_SYNTHETIC)

    def test_tampered_or_foreign_bundles_are_refused(self):
        copy = os.path.join(self.tmp, "tampered")
        shutil.copytree(self.bundle, copy)
        with open(os.path.join(copy, "preprocessing.json"), "a") as stream:
            stream.write(" ")
        with self.assertRaisesRegex(BundleError, "SHA-256"):
            DosDetector.load(copy)
        foreign = os.path.join(self.tmp, "foreign")
        shutil.copytree(self.bundle, foreign)
        with open(os.path.join(foreign, "bundle.json")) as stream:
            doc = json.load(stream)
        doc["schema_fingerprint"] = "0" * 64
        with open(os.path.join(foreign, "bundle.json"), "w") as stream:
            json.dump(doc, stream)
        with self.assertRaisesRegex(BundleError, "different feature schema"):
            DosDetector.load(foreign)

    def test_duplicate_windows_are_rejected_by_the_loader(self):
        dup = os.path.join(self.tmp, "dup-dataset")
        shutil.copytree(self.dataset, dup)
        for name in ("features.csv", "labels.csv", "splits.csv"):
            path = os.path.join(dup, name)
            with open(path, encoding="utf-8") as stream:
                lines = stream.readlines()
            with open(path, "w", encoding="utf-8", newline="") as stream:
                stream.writelines(lines + [lines[1]])
        with open(os.path.join(dup, "manifest.json")) as stream:
            manifest = json.load(stream)
        manifest["files"] = {n: sha256_file(os.path.join(dup, n)) for n in manifest["files"]}
        with open(os.path.join(dup, "manifest.json"), "w") as stream:
            json.dump(manifest, stream)
        with self.assertRaisesRegex(DataError, "duplicate window"):
            load_dataset(dup)

    def test_changed_dataset_files_are_rejected(self):
        changed = os.path.join(self.tmp, "changed-dataset")
        shutil.copytree(self.dataset, changed)
        with open(os.path.join(changed, "labels.csv"), "a") as stream:
            stream.write("x,1,2,attack,,\n")
        with self.assertRaisesRegex(DataError, "changed"):
            load_dataset(changed)

    def test_average_precision_matches_scikit_learn(self):
        from sklearn.metrics import average_precision_score
        rng = random.Random(7)
        scores = [rng.random() for _ in range(500)]
        labels = [rng.random() < 0.2 + 0.5 * s for s in scores]
        self.assertAlmostEqual(ev.average_precision(scores, labels), average_precision_score(labels, scores), places=10)

    # --- CLI, heuristic and payloads ---------------------------------------------------
    def test_cli_predict_scores_every_window_without_reading_labels(self):
        out = os.path.join(self.tmp, "predict-out")
        extraction = os.path.join(self.tmp, "fixture", "synthetic-test")
        self.assertEqual(ml_main(["predict", "--bundle", self.bundle, "--extraction", extraction, "--out-dir", out]), 0)
        with open(os.path.join(out, "run.json")) as stream:
            run = json.load(stream)
        self.assertFalse(run["labels_read"])
        self.assertEqual(run["counts"]["windows"], len(self.test_rows))
        with open(os.path.join(out, "alerts.jsonl")) as stream:
            payloads = [json.loads(line) for line in stream]
        self.assertTrue(payloads)
        self.assertTrue(all(p["attackType"] == "DOS_DDOS" and p["dataOrigin"] == "PCAP_REPLAY" for p in payloads))
        with open(os.path.join(out, "scores.csv"), newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(payloads), sum(r["raised"] == "1" for r in rows))   # one payload per episode
        self.assertGreater(run["counts"]["alert_windows"], len(payloads))
        self.assertLessEqual(len(payloads), 2 + 2)  # 2 synthetic floods on the victim (+ tolerance)
        pred = payloads[0]["evidence"][1]["fields"]
        self.assertIn("not a probability", pred["scoreSemantics"])
        self.assertEqual(set(pred["riskComponents"]), {"margin", "persistence", "volume"})
        self.assertTrue(all(p["confidenceTier"] in ("suspicious", "likely") for p in payloads))

    def test_cli_train_refusal_exit_code(self):
        out = os.path.join(self.tmp, "cli-refused")
        config = os.path.join(self.tmp, "strict.json")
        with open(config, "w") as stream:
            json.dump({"gates": {"min_train_attack_families": 5}}, stream)  # the fixture has 2
        self.assertEqual(ml_main(["train", "--dataset", self.dataset, "--config", config, "--out-dir", out]), 3)
        self.assertTrue(os.path.exists(os.path.join(out, "training_refused.json")))


@unittest.skipUnless(HAVE_ML, "numpy not installed (use the ml-service venv)")
class HeuristicAndTrackerTest(unittest.TestCase):
    def window(self, pps):
        row = {n: 0.0 for n in FEATURE_NAMES}
        row.update({n: math.nan for n in FEATURE_NAMES if n.startswith("tcp_") or n.endswith("_baseline")})
        row.update(in_pkts_per_s=pps, in_packets=pps * 5, schema_version=SCHEMA_VERSION,
                   window_start_ns=WINDOW_NS * 10, window_start_utc="2023-11-14T22:13:20Z", dst_ip="198.51.100.4")
        return row

    def test_heuristic_is_labelled_and_transparent(self):
        h = PpsHeuristic(threshold_pps=5000, k=3, n=3)
        r = h.score_window(self.window(5000))
        self.assertEqual(r["status"], STATUS_HEURISTIC)
        self.assertTrue(r["over_threshold"])
        self.assertFalse(h.score_window(self.window(4999))["over_threshold"])
        self.assertEqual(risk_score(r), 60)  # margin 0, full persistence, volume 0 at the threshold
        p = detection_payload(self.window(5000), r, organization_id="o", endpoint_id="e", data_origin="PCAP_REPLAY",
                              persistence=h.persistence)
        self.assertEqual((p["ruleId"], p["detectorStatus"], p["confidenceTier"]), ("DOS-PPS-HEURISTIC", "HEURISTIC", "suspicious"))
        self.assertEqual(p["indicators"][0]["observedAt"], "2023-11-14T22:13:20Z")  # the window time, not ingest time
        self.assertNotIn("label", json.dumps(p).lower().replace("labels", ""))
        with self.assertRaises(ValueError):
            detection_payload(self.window(5000), r, organization_id="o", endpoint_id="e", data_origin="SIMULATED",
                              persistence=h.persistence)

    def test_risk_assessment_is_bounded_monotonic_and_never_confirmed(self):
        model = {"score": 0.525, "threshold": 0.475, "status": "TRAINED", "volume_reference_pps": 470.8}
        weak = risk_assessment(model, pps=470.8, hits=2, n=3)
        strong = risk_assessment(model, pps=47080.0, hits=3, n=3)
        self.assertEqual(weak["riskScore"], round(40 + 20 * (0.05 / 0.525) + 20 * 2 / 3))
        self.assertEqual(weak["confidenceTier"], "suspicious")
        self.assertEqual(strong["components"]["volume"], 1.0)
        self.assertEqual(strong["confidenceTier"], "likely")
        self.assertGreater(strong["riskScore"], weak["riskScore"])
        for status in ("SYNTHETIC_TEST_ONLY", "HEURISTIC"):
            r = risk_assessment(dict(model, status=status, threshold=0.475 if status != "HEURISTIC" else 5000,
                                     score=0.525 if status != "HEURISTIC" else 500000), pps=10**6, hits=3, n=3)
            self.assertEqual(r["confidenceTier"], "suspicious", status)
            self.assertLessEqual(r["riskScore"], 100)
        lo = risk_assessment(dict(model, score=0.475), pps=1.0, hits=0, n=3)
        self.assertEqual(lo["riskScore"], 40)
        self.assertIn("not a probability", lo["formula"])

    def test_tracker_raises_once_per_episode(self):
        t = AlertTracker({"k": 2, "n": 3})
        s = lambda i: WINDOW_NS * (500 + i)
        raised = [t.observe("h", s(i), True)["raised"] for i in range(10)]
        self.assertEqual(raised, [False, True] + [False] * 8)
        for i in range(10, 14):
            state = t.observe("h", s(i), False)
        self.assertFalse(state["active"])
        self.assertFalse(t.observe("h", s(14), True)["raised"])
        self.assertTrue(t.observe("h", s(15), True)["raised"])   # a new episode after it cleared
        self.assertEqual(t.observe("h", s(16), True)["hits"], 3)

    def test_tracker_k_of_n_with_gaps_and_order(self):
        t = AlertTracker({"k": 2, "n": 3})
        s = lambda i: WINDOW_NS * (100 + i)
        self.assertFalse(t.update("h", s(0), True))
        self.assertTrue(t.update("h", s(1), True))
        self.assertFalse(t.update("h", s(5), True))   # gap of quiet slots
        self.assertTrue(t.update("h", s(6), True))
        self.assertFalse(t.update("g", s(6), True))   # hosts are independent
        with self.assertRaises(ValueError):
            t.update("h", s(6), True)


if __name__ == "__main__":
    unittest.main()
