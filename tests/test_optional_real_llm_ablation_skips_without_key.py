import os
import unittest
from unittest.mock import patch

from heimdall.evaluation.llm_ablation import run_gpt41mini_reasoning_ablation
from heimdall.evaluation.models import Alert


class OptionalRealLlmAblationTests(unittest.TestCase):
    def test_skips_without_key(self):
        alert = Alert(
            alert_id="A",
            vulnerability_type="SQL Injection",
            severity="high",
            file_path="app.py",
            line_number=1,
            code_snippet="x",
            endpoint="/",
            method="GET",
            parameters={},
            sast_message="message",
            ground_truth_label="true_positive",
        )
        with patch.dict(os.environ, {}, clear=True):
            result = run_gpt41mini_reasoning_ablation([alert])[0]
        self.assertEqual(result.prediction, "needs_review")
        self.assertEqual(result.error_category, "llm_ablation_not_run")


if __name__ == "__main__":
    unittest.main()
