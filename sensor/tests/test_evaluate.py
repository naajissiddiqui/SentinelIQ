import math
import unittest

from netsensor.evaluate import (
    attack_episodes,
    average_precision,
    detection_delays,
    persistent_alerts,
    pps_baseline_score,
    rates_at,
    recall_by_family,
    threshold_for_fpr,
)
from netsensor.schema import WINDOW_NS

T0 = 340_000_000 * WINDOW_NS


def slot(i):
    return T0 + i * WINDOW_NS


class AveragePrecisionTest(unittest.TestCase):
    def test_perfect_and_hand_computed(self):
        self.assertEqual(average_precision([0.9, 0.8, 0.1], [True, True, False]), 1.0)
        # Ranking P N P: AP = 0.5 * 1/1 + 0.5 * 2/3
        self.assertAlmostEqual(average_precision([0.9, 0.5, 0.1], [True, False, True]), 0.5 + 1 / 3)

    def test_ties_form_one_threshold(self):
        # All tied: one point, recall 1, precision 1/2.
        self.assertAlmostEqual(average_precision([1.0, 1.0], [True, False]), 0.5)

    def test_no_positives_is_nan_and_nan_scores_are_refused(self):
        self.assertTrue(math.isnan(average_precision([0.1], [False])))
        with self.assertRaises(ValueError):
            average_precision([math.nan], [True])


class ThresholdTest(unittest.TestCase):
    def test_threshold_respects_the_fpr_budget(self):
        neg = [float(i) for i in range(10)]  # 0..9
        scores, labels = neg + [20.0], [False] * 10 + [True]
        t = threshold_for_fpr(scores, labels, 0.1)  # one false positive allowed
        r = rates_at(scores, labels, t)
        self.assertLessEqual(r["fpr"], 0.1)
        self.assertEqual(r["fpr"], 0.1)
        self.assertGreater(t, 8.0)
        self.assertEqual(r["recall"], 1.0)
        self.assertEqual(rates_at(scores, labels, threshold_for_fpr(scores, labels, 0.0))["fpr"], 0.0)

    def test_threshold_from_validation_is_applied_unchanged_to_test(self):
        t = threshold_for_fpr([1.0, 2.0, 3.0, 10.0], [False, False, False, True], 0.0)
        test = rates_at([4.0, 2.5, 9.0], [False, True, True], t)
        self.assertEqual(test["fpr"], 1.0)  # reported honestly, not re-tuned
        self.assertEqual(test["recall"], 0.5)

    def test_recall_by_family(self):
        out = recall_by_family([5, 1, 5, 0], [True, True, True, False], ["UDP", "UDP", "SYN", ""], 2)
        self.assertEqual(out, {"SYN": {"recall": 1.0, "positives": 1}, "UDP": {"recall": 0.5, "positives": 2}})


class PersistenceAndDelayTest(unittest.TestCase):
    def test_k_of_n_with_a_missing_slot(self):
        windows = [("h", slot(0), 9), ("h", slot(1), 9), ("h", slot(3), 9), ("h", slot(4), 0)]
        self.assertEqual(persistent_alerts(windows, 5, 1, 1)["h"], [slot(0), slot(1), slot(3)])
        # 2 of 3: slot 2 is missing (not over threshold), so slot 3 still has 2 of {1,2,3}.
        self.assertEqual(persistent_alerts(windows, 5, 2, 3)["h"], [slot(1), slot(3)])
        self.assertEqual(persistent_alerts(windows, 5, 3, 3)["h"], [])
        with self.assertRaises(ValueError):
            persistent_alerts(windows, 5, 4, 3)

    def test_episodes_bridge_ambiguous_but_not_gaps(self):
        rows = [("h", slot(0), "benign"), ("h", slot(1), "attack"), ("h", slot(2), "ambiguous"),
                ("h", slot(3), "attack"), ("h", slot(5), "attack"), ("g", slot(0), "attack")]
        self.assertEqual(attack_episodes(rows),
                         [("g", slot(0), slot(0)), ("h", slot(1), slot(3)), ("h", slot(5), slot(5))])

    def test_delay_runs_to_the_end_of_the_alerting_window(self):
        episodes = [("h", slot(1), slot(4)), ("g", slot(0), slot(2))]
        alerts = {"h": [slot(0), slot(2)], "g": []}
        self.assertEqual(detection_delays(episodes, alerts), [10.0, None])

    def test_pps_baseline_reads_only_inbound_packet_rate(self):
        self.assertEqual(pps_baseline_score({"in_pkts_per_s": 12.5, "in_bytes": 1e9}), 12.5)


if __name__ == "__main__":
    unittest.main()
