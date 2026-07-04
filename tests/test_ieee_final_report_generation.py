import unittest

from scripts.generate_ieee_final_report import bootstrap_intervals, coverage_rows, dataset_summary


class IeeeFinalReportGenerationTests(unittest.TestCase):
    def test_bootstrap_and_dataset_summary_helpers(self):
        rows = [
            {"mode": "m", "classification": "TP", "ground_truth_label": "true_positive"},
            {"mode": "m", "classification": "TN", "ground_truth_label": "false_positive"},
        ]
        ci = bootstrap_intervals(rows, iterations=10)
        self.assertIn("coverage", ci["m"])
        summary = {"modes": {"m": {"coverage": 1, "decision_rate": 1, "abstention_rate": 0, "selective_precision": 1, "selective_recall": 1, "false_negative_risk": 0, "false_positive_pass_through_rate": 0, "review_burden_reduction": 1, "confirmed_true_positive_rate": 1, "utility_score": 1}}}
        self.assertIn("coverage_ci95_low", coverage_rows(summary, ci)[0])
        dataset = dataset_summary([{"vulnerability_type": "SQL Injection", "ground_truth_label": "true_positive", "severity": "high", "source": "active_local_fixture", "active_local_fixture": True}])
        self.assertEqual(dataset["active_local_fixtures"], 1)


if __name__ == "__main__":
    unittest.main()
