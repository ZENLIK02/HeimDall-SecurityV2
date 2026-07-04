import unittest
from collections import Counter

from scripts.generate_active_local_dataset import CATEGORIES, TOTAL_ACTIVE_ALERTS, generate_dataset


class ActiveLocalDatasetTests(unittest.TestCase):
    def test_generates_expanded_balanced_alerts(self):
        alerts = generate_dataset()
        self.assertEqual(len(alerts), TOTAL_ACTIVE_ALERTS)
        by_category = Counter(alert["vulnerability_type"] for alert in alerts)
        self.assertEqual(set(by_category), set(CATEGORIES))
        self.assertTrue(all(count == 15 for count in by_category.values()))
        by_behavior = Counter(alert["expected_validation_behavior"] for alert in alerts)
        self.assertGreaterEqual(by_behavior["confirmable_active_local"], 90)
        self.assertGreaterEqual(by_behavior["dismissible_false_positive"], 40)
        self.assertGreaterEqual(by_behavior["needs_review"], 40)

    def test_rows_are_loader_compatible(self):
        required = {
            "alert_id",
            "vulnerability_type",
            "severity",
            "file_path",
            "line_number",
            "code_snippet",
            "endpoint",
            "method",
            "parameters",
            "sast_message",
            "ground_truth_label",
            "notes",
        }
        for alert in generate_dataset():
            self.assertTrue(required.issubset(alert))
            self.assertIn("message", alert)
            self.assertIn("endpoint_hint", alert)
            self.assertIn("expected_evidence_marker", alert)
            self.assertEqual(alert["source"], "active_local_fixture")
            self.assertTrue(alert["target_base_url"].startswith("http://127.0.0.1:5005"))
            self.assertTrue(alert["active_local_fixture"])


if __name__ == "__main__":
    unittest.main()
