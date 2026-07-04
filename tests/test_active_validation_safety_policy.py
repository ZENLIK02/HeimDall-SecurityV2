import unittest

from heimdall.config import DastRuntimeConfig, HeimdallConfig, LLMConfig, ReportsConfig, SecurityConfig, SemgrepConfig
from heimdall.evaluation.active_local import is_local_url_allowed, validate_alert
from heimdall.evaluation.models import Alert


def active_alert(parameters=None):
    return Alert(
        alert_id="safe",
        vulnerability_type="Command Injection",
        severity="high",
        file_path="local_lab/vulnerable_app/app.py",
        line_number=1,
        code_snippet="fixture",
        endpoint="/cmd/vulnerable",
        method="GET",
        parameters=parameters or {"cmd": "fake-date"},
        sast_message="message",
        ground_truth_label="true_positive",
        notes="",
        metadata={
            "expected_evidence_marker": "HEIMDALL_CMD_MARKER",
            "expected_validation_behavior": "confirmable_active_local",
            "active_local_fixture": True,
            "target_base_url": "http://127.0.0.1:5005",
        },
    )


class ActiveValidationSafetyPolicyTests(unittest.TestCase):
    def test_non_local_target_rejected(self):
        self.assertFalse(is_local_url_allowed("https://example.com", ("http://127.0.0.1:5005",)))

    def test_kill_switch_blocks_validation(self):
        config = HeimdallConfig(
            SecurityConfig(kill_switch=True),
            DastRuntimeConfig(),
            LLMConfig(),
            ReportsConfig(),
            SemgrepConfig(),
        )
        result = validate_alert(active_alert(), config)
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.error_category, "safety_policy_abstention")

    def test_destructive_payload_blocked(self):
        config = HeimdallConfig(SecurityConfig(), DastRuntimeConfig(), LLMConfig(), ReportsConfig(), SemgrepConfig())
        result = validate_alert(active_alert({"cmd": "rm -rf /"}), config)
        self.assertEqual(result.error_category, "safety_policy_abstention")


if __name__ == "__main__":
    unittest.main()
