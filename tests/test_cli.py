import json
import tempfile
import unittest
from pathlib import Path

from heimdall.cli import main


class CliTests(unittest.TestCase):
    def test_check_config(self):
        self.assertEqual(main(["check-config", "--config", "heimdall.yml"]), 0)

    def test_validate_generates_ci_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main(
                [
                    "validate",
                    "--semgrep",
                    "test_data/semgrep-results-sample.json",
                    "--config",
                    "heimdall.yml",
                    "--output",
                    tmp,
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue((Path(tmp) / "ci_summary.md").exists())

    def test_bounded_dast_command_abstains_without_runtime_authorization(self):
        row = {
            "alert_id": "targetless-1",
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 1,
            "code_snippet": "query = user_input",
            "endpoint": "/sql",
            "method": "GET",
            "parameters": {"username": "probe"},
            "sast_message": "possible SQL injection",
            "ground_truth_label": "true_positive",
            "notes": "No runtime mapping.",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "alerts.jsonl"
            output = root / "report"
            dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
            code = main(
                [
                    "bounded-dast",
                    "--dataset",
                    str(dataset),
                    "--config",
                    "heimdall.yml",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 0)
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["request_count"], 0)
            self.assertEqual(summary["metrics"]["manual_review"], 1)


if __name__ == "__main__":
    unittest.main()
