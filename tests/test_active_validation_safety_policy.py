import unittest

from heimdall.config import (
    ActiveValidationConfig,
    DastRuntimeConfig,
    HeimdallConfig,
    LLMConfig,
    ReportsConfig,
    SecurityConfig,
    SemgrepConfig,
)
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
    @staticmethod
    def enabled_config(*, kill_switch=False):
        return HeimdallConfig(
            SecurityConfig(kill_switch=kill_switch),
            DastRuntimeConfig(),
            LLMConfig(),
            ReportsConfig(),
            SemgrepConfig(),
            ActiveValidationConfig(enabled=True),
        )

    def test_non_local_target_rejected(self):
        self.assertFalse(is_local_url_allowed("https://example.com", ("http://127.0.0.1:5005",)))

    def test_kill_switch_blocks_validation(self):
        config = self.enabled_config(kill_switch=True)
        result = validate_alert(active_alert(), config)
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.error_category, "safety_policy_abstention")

    def test_destructive_payload_blocked(self):
        config = self.enabled_config()
        result = validate_alert(active_alert({"cmd": "rm -rf /"}), config)
        self.assertEqual(result.error_category, "safety_policy_abstention")

    def test_external_url_inside_payload_is_blocked(self):
        result = validate_alert(active_alert({"url": "https://example.com/callback"}), self.enabled_config())
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.metadata["bounded_dast"]["request_count"], 0)
        self.assertEqual(result.metadata["bounded_dast"]["reason"], "external_url_in_payload")

    def test_non_get_post_method_is_blocked(self):
        source = active_alert()
        alert = Alert(**{**source.__dict__, "method": "DELETE"})
        result = validate_alert(alert, self.enabled_config())
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.metadata["bounded_dast"]["reason"], "unsupported_http_method")

    def test_absolute_endpoint_is_blocked(self):
        source = active_alert()
        alert = Alert(**{**source.__dict__, "endpoint": "http://127.0.0.1:5005/cmd/vulnerable"})
        result = validate_alert(alert, self.enabled_config())
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.metadata["bounded_dast"]["reason"], "absolute_endpoint_not_allowed")

    def test_missing_evidence_predicate_abstains_without_request(self):
        source = active_alert()
        alert = Alert(
            **{
                **source.__dict__,
                "vulnerability_type": "Unsupported Category",
                "metadata": {
                    **source.metadata,
                    "expected_evidence_marker": "",
                },
            }
        )
        result = validate_alert(alert, self.enabled_config())
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.error_category, "missing_evidence_predicate")
        self.assertEqual(result.metadata["bounded_dast"]["request_count"], 0)


if __name__ == "__main__":
    unittest.main()
