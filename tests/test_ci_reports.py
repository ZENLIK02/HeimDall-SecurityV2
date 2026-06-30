import tempfile
import unittest
from pathlib import Path

from heimdall.ci_reports import write_ci_reports
from heimdall.config import DastRuntimeConfig, HeimdallConfig, LLMConfig, ReportsConfig, SecurityConfig, SemgrepConfig
from heimdall.evaluation.models import EvaluationResult


class CiReportTests(unittest.TestCase):
    def test_writes_markdown_report(self):
        config = HeimdallConfig(SecurityConfig(), DastRuntimeConfig(), LLMConfig(), ReportsConfig(), SemgrepConfig())
        result = EvaluationResult(
            alert_id="rule.xss",
            mode="ci",
            vulnerability_type="XSS",
            severity="high",
            ground_truth_label="true_positive",
            prediction="needs_review",
            classification="REVIEW",
            confidence=0.5,
            final_decision="Needs Review",
            evidence="dry-run only",
            recommended_action="Review manually.",
        )
        with tempfile.TemporaryDirectory() as tmp:
            write_ci_reports(tmp, [result], 1, config)
            text = (Path(tmp) / "ci_summary.md").read_text(encoding="utf-8")
            self.assertIn("Total Semgrep findings", text)
            self.assertIn("rule.xss", text)


if __name__ == "__main__":
    unittest.main()
