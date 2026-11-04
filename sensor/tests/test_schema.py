import unittest

from netsensor import schema


class SchemaTest(unittest.TestCase):
    def test_no_forbidden_or_key_column_is_a_feature(self):
        for names in (schema.FEATURE_NAMES, schema.FLOW_FEATURE_NAMES):
            self.assertFalse(set(names) & schema.FORBIDDEN_FEATURES)
            self.assertFalse(set(names) & set(schema.KEY_COLUMNS))
            self.assertFalse(set(names) & set(schema.FLOW_KEY_COLUMNS))
            self.assertEqual(len(names), len(set(names)))

    def test_guard_rejects_identifying_columns(self):
        for bad in ("dst_ip", "src_port", "flow_id", "timestamp", "label", "ttl", "window_start_ns"):
            with self.assertRaises(ValueError):
                schema.assert_feature_names_safe(["in_packets", bad])
        with self.assertRaises(ValueError):
            schema.assert_feature_names_safe(["in_packets", "in_packets"])

    def test_fingerprint_is_stable_and_tracks_the_schema(self):
        first = schema.schema_fingerprint()
        self.assertEqual(first, schema.schema_fingerprint())
        original = list(schema.FEATURE_NAMES)
        try:
            schema.FEATURE_NAMES.reverse()
            self.assertNotEqual(first, schema.schema_fingerprint())
        finally:
            schema.FEATURE_NAMES[:] = original

    def test_feature_vector_follows_schema_order_and_refuses_gaps(self):
        row = {name: float(i) for i, name in enumerate(schema.FEATURE_NAMES)}
        row["dst_ip"] = "192.0.2.1"  # ignored: not a feature
        self.assertEqual(schema.feature_vector(row), [float(i) for i in range(len(schema.FEATURE_NAMES))])
        del row["in_packets"]
        with self.assertRaises(KeyError):
            schema.feature_vector(row)


if __name__ == "__main__":
    unittest.main()
