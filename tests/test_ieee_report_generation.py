import unittest

from scripts.generate_ieee_ready_report import coverage_rows, dataset_summary, metrics_rows


class IeeeReportGenerationTests(unittest.TestCase):
    def test_report_helpers_format_summary_rows(self):
        summary = {
            "modes": {
                "sast_only": {
                    "total": 1,
                    "tp": 1,
                    "fp": 0,
                    "tn": 0,
                    "fn": 0,
                    "manual_review": 0,
                    "manual_review_real": 0,
                    "manual_review_false": 0,
                    "accuracy": 1.0,
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1_score": 1.0,
                    "false_positive_reduction_rate": 0.0,
                    "manual_review_rate": 0.0,
                    "coverage": 1.0,
                    "decision_rate": 1.0,
                    "abstention_rate": 0.0,
                    "selective_precision": 1.0,
                    "selective_recall": 1.0,
                    "false_negative_risk": 0.0,
                    "false_positive_pass_through_rate": 0.0,
                    "review_burden_reduction": 1.0,
                    "confirmed_true_positive_rate": 1.0,
                    "utility_score": 1.0,
                }
            }
        }
        self.assertEqual(metrics_rows(summary)[0]["mode"], "sast_only")
        self.assertEqual(coverage_rows(summary)[0]["coverage"], "1.0000")
        dataset = dataset_summary(
            [
                {
                    "vulnerability_type": "SQL Injection",
                    "ground_truth_label": "true_positive",
                    "severity": "high",
                    "active_local_fixture": True,
                }
            ]
        )
        self.assertEqual(dataset["active_local_fixtures"], 1)


if __name__ == "__main__":
    unittest.main()
