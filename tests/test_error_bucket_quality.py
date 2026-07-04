import unittest

from heimdall.evaluation.error_analysis import group_error_cases
from heimdall.evaluation.models import EvaluationResult


class ErrorBucketQualityTests(unittest.TestCase):
    def test_new_error_buckets_are_preserved(self):
        result = EvaluationResult(
            alert_id="A",
            mode="heimdall_active_local_validation",
            vulnerability_type="IDOR",
            severity="high",
            ground_truth_label="true_positive",
            prediction="needs_review",
            classification="REVIEW",
            confidence=0.5,
            error_category="missing_authentication_context",
        )
        buckets = group_error_cases([result])
        self.assertEqual(buckets["missing_authentication_context"], 1)
        self.assertEqual(buckets["ambiguous response"], 0)


if __name__ == "__main__":
    unittest.main()
