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


if __name__ == "__main__":
    unittest.main()
