import unittest

from heimdall.pipeline.dast_executor import SafeDastExecutor
from heimdall.pipeline.models import DastConfig, ValidationPayload


class DastExecutorTests(unittest.TestCase):
    def test_blocks_non_allowlisted_host(self):
        executor = SafeDastExecutor(DastConfig(target_base_url="http://example.com", dry_run=True))
        result = executor.execute(ValidationPayload("XSS", "GET", "/", parameters={"q": "test"}))
        self.assertEqual(result.status, "blocked")
        self.assertIn("not allowlisted", result.blocked_reason)

    def test_dry_run_does_not_send_network_request(self):
        executor = SafeDastExecutor(DastConfig(target_base_url="http://127.0.0.1:3000", dry_run=True))
        result = executor.execute(ValidationPayload("SQL Injection", "POST", "/login", parameters={"username": "' OR '1'='1"}))
        self.assertTrue(result.dry_run)
        self.assertEqual(result.status, "not_confirmed")
        self.assertTrue(result.request_log)


if __name__ == "__main__":
    unittest.main()

