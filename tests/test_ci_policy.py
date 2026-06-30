import unittest

from heimdall.ci_policy import determine_exit_code
from heimdall.config import DastRuntimeConfig, HeimdallConfig, LLMConfig, ReportsConfig, SecurityConfig, SemgrepConfig
from heimdall.evaluation.models import EvaluationResult


def config():
    return HeimdallConfig(SecurityConfig(), DastRuntimeConfig(), LLMConfig(), ReportsConfig(), SemgrepConfig())


def result(severity, decision):
    return EvaluationResult(
        alert_id="A",
        mode="ci",
        vulnerability_type="XSS",
        severity=severity,
        ground_truth_label="true_positive",
        prediction="confirmed" if decision == "True Positive" else "needs_review",
        classification="TP" if decision == "True Positive" else "REVIEW",
        confidence=0.9,
        final_decision=decision,
    )


class CiPolicyTests(unittest.TestCase):
    def test_fails_on_confirmed_high(self):
        self.assertEqual(determine_exit_code([result("high", "True Positive")], config()), 1)

    def test_needs_review_does_not_fail(self):
        self.assertEqual(determine_exit_code([result("high", "Needs Review")], config()), 0)


if __name__ == "__main__":
    unittest.main()
