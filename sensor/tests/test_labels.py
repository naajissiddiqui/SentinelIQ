import json
import unittest

from netsensor.labels import AMBIGUOUS, ATTACK, BENIGN, LabelRuleError, describe, parse_rules
from netsensor.schema import WINDOW_NS

S = 1_000_000_000
T0 = 1_700_000_000 * S  # on the 5 s grid
VICTIM = "198.51.100.20"
OTHER = "198.51.100.21"


def rules_doc(intervals=None, verified=True, guard=10, **provenance):
    prov = {"source": "unit-test fixture", "verified": verified,
            "verified_by": "unit test", "verified_on": "2026-10-18"}
    prov.update(provenance)
    if intervals is None:
        intervals = [{"id": "a", "family": "UDP", "start": "2023-11-14T22:14:00+00:00",
                      "end": "2023-11-14T22:16:00+00:00", "victims": [VICTIM]}]
    return json.dumps({"label_rules_version": "test-v1", "dataset": "fixture",
                       "provenance": prov, "guard_seconds": guard,
                       "intervals": intervals}).encode()


def iso(ns):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ns // S, timezone.utc).isoformat()


class RuleValidationTest(unittest.TestCase):
    def test_naive_timestamp_is_refused(self):
        doc = rules_doc([{"id": "a", "family": "UDP", "start": "2023-11-14T22:14:00",
                          "end": "2023-11-14T22:16:00+00:00", "victims": [VICTIM]}])
        with self.assertRaisesRegex(LabelRuleError, "no UTC offset"):
            parse_rules(doc)

    def test_unverified_rules_are_refused_unless_allowed(self):
        doc = rules_doc(verified=False)
        with self.assertRaisesRegex(LabelRuleError, "not verified"):
            parse_rules(doc)
        rules = parse_rules(doc, allow_unverified=True)
        self.assertFalse(rules.verified)
        self.assertFalse(describe(rules)["trusted"])

    def test_verified_rules_must_name_who_verified_them(self):
        with self.assertRaisesRegex(LabelRuleError, "verified_by"):
            parse_rules(rules_doc(verified_by=""))

    def test_malformed_intervals_are_refused(self):
        good = {"id": "a", "family": "UDP", "start": iso(T0), "end": iso(T0 + 60 * S), "victims": [VICTIM]}
        cases = {
            "end is not after start": dict(good, end=iso(T0)),
            "invalid victim": dict(good, victims=["not-an-ip"]),
            "victims must be": dict(good, victims=[]),
            "id and family": dict(good, family=""),
        }
        for message, interval in cases.items():
            with self.subTest(message):
                with self.assertRaisesRegex(LabelRuleError, message):
                    parse_rules(rules_doc([interval]))
        with self.assertRaisesRegex(LabelRuleError, "duplicate id"):
            parse_rules(rules_doc([good, good]))
        with self.assertRaisesRegex(LabelRuleError, "non-empty list"):
            parse_rules(rules_doc([]))

    def test_rules_hash_identifies_the_exact_file(self):
        self.assertNotEqual(parse_rules(rules_doc(guard=10)).sha256, parse_rules(rules_doc(guard=5)).sha256)


class LabellingTest(unittest.TestCase):
    def setUp(self):
        # Attack from T0+60 s to T0+180 s, guard 10 s: core is [T0+70, T0+170).
        self.rules = parse_rules(rules_doc(
            [{"id": "u1", "family": "UDP", "start": iso(T0 + 60 * S), "end": iso(T0 + 180 * S),
              "victims": [VICTIM]}], guard=10))

    def label(self, offset_s, host=VICTIM):
        return self.rules.label(T0 + offset_s * S, host)[0]

    def test_core_guard_and_outside(self):
        self.assertEqual(self.label(70), ATTACK)
        self.assertEqual(self.label(165), ATTACK)     # [165, 170) ends at the core edge
        self.assertEqual(self.label(65), AMBIGUOUS)   # inside the interval, inside the guard
        self.assertEqual(self.label(170), AMBIGUOUS)
        self.assertEqual(self.label(50), AMBIGUOUS)   # before the interval, inside the guard
        self.assertEqual(self.label(45), BENIGN)      # [45, 50) ends where the guard starts
        self.assertEqual(self.label(190), BENIGN)
        self.assertEqual(self.rules.label(T0 + 100 * S, VICTIM), (ATTACK, "UDP", "u1"))

    def test_non_victim_is_benign_during_an_attack(self):
        self.assertEqual(self.label(100, host=OTHER), BENIGN)

    def test_competing_families_are_ambiguous_same_family_is_not(self):
        base = {"start": iso(T0), "end": iso(T0 + 120 * S), "victims": [VICTIM]}
        mixed = parse_rules(rules_doc([dict(base, id="a", family="UDP"), dict(base, id="b", family="SYN")], guard=0))
        same = parse_rules(rules_doc([dict(base, id="a", family="UDP"), dict(base, id="b", family="UDP")], guard=0))
        self.assertEqual(mixed.label(T0 + 30 * S, VICTIM)[0], AMBIGUOUS)
        self.assertEqual(same.label(T0 + 30 * S, VICTIM)[0], ATTACK)

    def test_exclude_interval_makes_non_core_windows_ambiguous(self):
        rules = parse_rules(rules_doc([
            {"id": "flood", "family": "UDP", "start": iso(T0 + 60 * S), "end": iso(T0 + 180 * S), "victims": [VICTIM]},
            {"id": "day", "kind": "exclude", "start": iso(T0), "end": iso(T0 + 600 * S), "victims": [VICTIM, OTHER]},
        ], guard=10))
        self.assertEqual(rules.label(T0 + 100 * S, VICTIM), (ATTACK, "UDP", "flood"))  # core wins
        self.assertEqual(rules.label(T0 + 300 * S, VICTIM)[0], AMBIGUOUS)  # trickle zone
        self.assertEqual(rules.label(T0 + 300 * S, OTHER)[0], AMBIGUOUS)
        self.assertEqual(rules.label(T0 + 600 * S, VICTIM)[0], BENIGN)     # after the exclude interval
        self.assertEqual(rules.label(T0 + 300 * S, "192.0.2.99")[0], BENIGN)

    def test_exclude_only_rules_and_bad_kinds_are_refused(self):
        exclude = {"id": "day", "kind": "exclude", "start": iso(T0), "end": iso(T0 + 60 * S), "victims": [VICTIM]}
        with self.assertRaisesRegex(LabelRuleError, "at least one attack interval"):
            parse_rules(rules_doc([exclude]))
        with self.assertRaisesRegex(LabelRuleError, "kind must be"):
            parse_rules(rules_doc([dict(exclude, kind="maybe")]))

    def test_zero_guard_labels_every_overlapping_window_attack(self):
        rules = parse_rules(rules_doc([{"id": "a", "family": "UDP", "start": iso(T0),
                                        "end": iso(T0 + 2 * WINDOW_NS), "victims": [VICTIM]}], guard=0))
        self.assertEqual(rules.label(T0, VICTIM)[0], ATTACK)
        self.assertEqual(rules.label(T0 + WINDOW_NS, VICTIM)[0], ATTACK)
        self.assertEqual(rules.label(T0 + 2 * WINDOW_NS, VICTIM)[0], BENIGN)


if __name__ == "__main__":
    unittest.main()
