import tempfile
import unittest
from pathlib import Path

from heimdall.config import ConfigError, load_config


VALID_CONFIG = """
security:
  dry_run: true
  allowed_targets:
    - "http://localhost:5000"
  blocked_targets:
    - "https://production.example.com"
  fail_on_confirmed_high: true
  fail_on_confirmed_critical: true
  needs_review_does_not_fail: true
dast:
  max_requests_per_scan: 10
  request_timeout_seconds: 5
llm:
  provider: "mock"
  use_mock_llm: true
reports:
  output_dir: "reports"
semgrep:
  output_path: "semgrep-results.json"
"""


class ConfigTests(unittest.TestCase):
    def test_loads_safe_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "heimdall.yml"
            path.write_text(VALID_CONFIG, encoding="utf-8")
            config = load_config(path)
            self.assertTrue(config.security.dry_run)
            self.assertEqual(config.dast.max_requests_per_scan, 10)

    def test_rejects_external_target_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "heimdall.yml"
            path.write_text(VALID_CONFIG.replace("http://localhost:5000", "https://example.com"), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
