import unittest

from heimdall.evaluation.metrics import calculate_metrics, classify
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


class MetricsTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify(True, "confirmed"), "TP")
        self.assertEqual(classify(False, "confirmed"), "FP")
        self.assertEqual(classify(False, "dismissed"), "TN")
        self.assertEqual(classify(True, "dismissed"), "FN")
        self.assertEqual(classify(True, "needs_review"), "REVIEW")

    def test_calculate_metrics(self):
        metrics = calculate_metrics([result("TP"), result("FP"), result("TN"), result("FN"), result("REVIEW")])
        self.assertEqual(metrics["tp"], 1)
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["tn"], 1)
        self.assertEqual(metrics["fn"], 1)
        self.assertEqual(metrics["manual_review"], 1)
        self.assertAlmostEqual(metrics["accuracy"], 0.4)
        self.assertAlmostEqual(metrics["precision"], 0.5)
        self.assertAlmostEqual(metrics["recall"], 0.5)
        self.assertAlmostEqual(metrics["f1_score"], 0.5)
        self.assertAlmostEqual(metrics["false_positive_reduction_rate"], 0.5)
        self.assertAlmostEqual(metrics["manual_review_rate"], 0.2)


if __name__ == "__main__":
    unittest.main()

