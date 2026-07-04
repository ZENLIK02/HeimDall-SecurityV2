import unittest
from pathlib import Path


class ReproducibilityRunnerTests(unittest.TestCase):
    def test_final_runner_contains_required_safety_steps(self):
        text = Path("scripts/run_ieee_final_evaluation.sh").read_text(encoding="utf-8")
        self.assertIn("heimdall_combined_ieee_alerts.jsonl", text)
        self.assertIn("127.0.0.1:5005/health", text)
        self.assertIn("allow_external_targets", text)
        self.assertIn("pytest", text)


if __name__ == "__main__":
    unittest.main()
