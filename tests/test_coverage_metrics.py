import unittest

from heimdall.evaluation.metrics import calculate_metrics
from heimdall.evaluation.models import EvaluationResult


def result(classification):
    mapping = {
        "TP": ("true_positive", "confirmed"),
        "FP": ("false_positive", "confirmed"),
        "TN": ("false_positive", "dismissed"),
        "FN": ("true_positive", "dismissed"),
        "REVIEW": ("true_positive", "needs_review"),
    }
    label, prediction = mapping[classification]
    return EvaluationResult(
        alert_id=classification,
        mode="test",
        vulnerability_type="XSS",
        severity="high",
        ground_truth_label=label,
        prediction=prediction,
        classification=classification,
        confidence=0.5,
    )


class CoverageMetricsTests(unittest.TestCase):
    def test_selective_and_coverage_metrics_are_reported(self):
        metrics = calculate_metrics([result("TP"), result("TN"), result("REVIEW")])
        self.assertAlmostEqual(metrics["coverage"], 2 / 3)
        self.assertAlmostEqual(metrics["decision_rate"], 2 / 3)
        self.assertAlmostEqual(metrics["abstention_rate"], 1 / 3)
        self.assertIn("selective_precision", metrics)
        self.assertIn("utility_score", metrics)


if __name__ == "__main__":
    unittest.main()
