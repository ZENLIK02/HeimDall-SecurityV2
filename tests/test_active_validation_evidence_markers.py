import unittest

from heimdall.evaluation.active_local import analyze_active_response
from heimdall.evaluation.models import Alert


def alert(category="SQL Injection", marker="HEIMDALL_SQLI_MARKER", negative_marker=""):
    return Alert(
        alert_id="marker",
        vulnerability_type=category,
        severity="high",
        file_path="local_lab/vulnerable_app/app.py",
        line_number=1,
        code_snippet="fixture",
        endpoint="/sql/vulnerable",
        method="GET",
        parameters={},
        sast_message="message",
        ground_truth_label="true_positive",
        notes="",
        metadata={
            "expected_evidence_marker": marker,
            "expected_negative_evidence_marker": negative_marker,
            "active_local_fixture": True,
        },
    )


class ActiveValidationEvidenceMarkerTests(unittest.TestCase):
    def test_marker_confirms(self):
        prediction, _, _, bucket = analyze_active_response(alert(), {"status_code": 200, "body": "HEIMDALL_SQLI_MARKER", "location": ""})
        self.assertEqual(prediction, "confirmed")
        self.assertEqual(bucket, "bounded_dast_confirmed")

    def test_marker_absent_requires_review(self):
        prediction, _, _, bucket = analyze_active_response(alert(), {"status_code": 200, "body": "safe", "location": ""})
        self.assertEqual(prediction, "needs_review")
        self.assertEqual(bucket, "insufficient_runtime_evidence")

    def test_declared_negative_marker_is_not_reproduced(self):
        prediction, _, _, bucket = analyze_active_response(
            alert(negative_marker="parameterized query rejected"),
            {"status_code": 400, "body": "parameterized query rejected", "location": ""},
        )
        self.assertEqual(prediction, "dismissed")
        self.assertEqual(bucket, "bounded_dast_not_reproduced")


if __name__ == "__main__":
    unittest.main()
