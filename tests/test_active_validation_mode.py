import threading
import time
import unittest
import urllib.request

from werkzeug.serving import make_server

from heimdall.evaluation.active_local import run_active_local_validation
from heimdall.evaluation.models import Alert
from local_lab.vulnerable_app.app import app


class ServerHandle:
    def __init__(self):
        self.server = None
        self.thread = None

    def start_if_needed(self):
        if _healthy():
            return
        self.server = make_server("127.0.0.1", 5005, app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        for _ in range(20):
            if _healthy():
                return
            time.sleep(0.1)

    def stop(self):
        if self.server is not None:
            self.server.shutdown()


def _healthy():
    try:
        with urllib.request.urlopen("http://127.0.0.1:5005/health", timeout=0.5) as response:
            return response.status == 200
    except Exception:
        return False


def alert(alert_id, endpoint, label, expected_evidence, behavior, parameters=None, negative_evidence=""):
    return Alert(
        alert_id=alert_id,
        vulnerability_type="SQL Injection",
        severity="high",
        file_path="local_lab/vulnerable_app/app.py",
        line_number=1,
        code_snippet="sql fixture",
        endpoint=endpoint,
        method="GET",
        parameters=parameters or {"username": "alice' OR '1'='1"},
        sast_message="possible SQL injection",
        ground_truth_label=label,
        notes="active fixture",
        metadata={
            "target_base_url": "http://127.0.0.1:5005",
            "expected_evidence": expected_evidence,
            "expected_negative_evidence_marker": negative_evidence,
            "expected_validation_behavior": behavior,
            "active_local_fixture": True,
        },
    )


class ActiveValidationModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = ServerHandle()
        cls.handle.start_if_needed()

    @classmethod
    def tearDownClass(cls):
        cls.handle.stop()

    def test_active_mode_confirms_dismisses_and_abstains(self):
        results = run_active_local_validation(
            [
                alert("tp", "/sql/vulnerable", "true_positive", "HEIMDALL_SQLI_MARKER", "confirmable_active_local"),
                alert(
                    "tn",
                    "/sql/safe",
                    "false_positive",
                    "HEIMDALL_SQLI_MARKER",
                    "dismissible_false_positive",
                    negative_evidence="parameterized query rejected",
                ),
                alert("review", "/review/auth-required", "true_positive", "HEIMDALL_SQLI_MARKER", "needs_review"),
            ]
        )
        self.assertEqual([result.classification for result in results], ["TP", "TN", "REVIEW"])
        self.assertEqual(results[0].metadata["bounded_dast"]["request_count"], 1)
        self.assertEqual(results[1].final_decision, "Not Reproduced Under Test")
        self.assertNotIn("body_excerpt", results[0].metadata["bounded_dast"])

    def test_response_capture_is_bounded(self):
        result = run_active_local_validation(
            [
                alert(
                    "large",
                    "/test/large-response",
                    "true_positive",
                    "HEIMDALL_LARGE_MARKER",
                    "confirmable_active_local",
                )
            ]
        )[0]
        metadata = result.metadata["bounded_dast"]
        self.assertEqual(result.prediction, "confirmed")
        self.assertEqual(metadata["response_bytes_captured"], 65536)
        self.assertTrue(metadata["response_truncated"])


if __name__ == "__main__":
    unittest.main()
