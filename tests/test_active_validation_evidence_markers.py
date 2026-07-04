import unittest

from heimdall.evaluation.active_local import analyze_active_response
from heimdall.evaluation.models import Alert


def alert(category="SQL Injection", marker="HEIMDALL_SQLI_MARKER"):
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
        metadata={"expected_evidence_marker": marker, "active_local_fixture": True},
    )


class ActiveValidationEvidenceMarkerTests(unittest.TestCase):
    def test_marker_confirms(self):
        prediction, _, _, bucket = analyze_active_response(alert(), {"status_code": 200, "body": "HEIMDALL_SQLI_MARKER", "location": ""})
        self.assertEqual(prediction, "confirmed")
        self.assertEqual(bucket, "active_validation_confirmed")

    def test_marker_absent_dismisses(self):
        prediction, _, _, bucket = analyze_active_response(alert(), {"status_code": 200, "body": "safe", "location": ""})
        self.assertEqual(prediction, "dismissed")
        self.assertEqual(bucket, "evidence_marker_absent")


if __name__ == "__main__":
    unittest.main()
