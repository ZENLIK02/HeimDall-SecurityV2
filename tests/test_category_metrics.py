import unittest

from scripts.generate_ieee_final_report import category_metrics


class CategoryMetricsTests(unittest.TestCase):
    def test_category_metrics_include_coverage_and_counts(self):
        rows = [
            {"mode": "m", "vulnerability_type": "SQL Injection", "classification": "TP"},
            {"mode": "m", "vulnerability_type": "SQL Injection", "classification": "TN"},
            {"mode": "m", "vulnerability_type": "SQL Injection", "classification": "REVIEW"},
        ]
        metrics = category_metrics(rows)[0]
        self.assertEqual(metrics["category_TP"], 1)
        self.assertEqual(metrics["category_TN"], 1)
        self.assertEqual(metrics["category_NeedsReview"], 1)
        self.assertEqual(metrics["category_coverage"], "0.6667")


if __name__ == "__main__":
    unittest.main()
