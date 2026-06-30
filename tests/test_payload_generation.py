import unittest

from heimdall.pipeline.context_extraction import extract_context
from heimdall.pipeline.payload_generation import generate_safe_payloads
from heimdall.pipeline.safety import SafetyController
from heimdall.pipeline.models import DastConfig, ValidationPayload
from heimdall.evaluation.models import Alert


class PayloadGenerationTests(unittest.TestCase):
    def test_generates_non_destructive_payload_for_each_supported_type(self):
        vuln_types = [
            "XSS",
            "SQL Injection",
            "Command Injection",
            "Path Traversal",
            "SSRF",
            "Broken Access Control / IDOR",
            "Business Logic Flaw",
        ]
        controller = SafetyController(DastConfig())
        for vuln_type in vuln_types:
            alert = Alert("A", vuln_type, "high", "app.py", 1, "snippet", "/test", "GET", {}, "message", "true_positive", "")
            payload = generate_safe_payloads(extract_context(alert))[0]
            safe, reason = controller.validate_payload(payload)
            self.assertTrue(safe, reason)

    def test_blocks_destructive_payload(self):
        controller = SafetyController(DastConfig())
        payload = ValidationPayload("Command Injection", "POST", "/x", parameters={"cmd": "rm -rf /"})
        safe, reason = controller.validate_payload(payload)
        self.assertFalse(safe)
        self.assertIn("destructive", reason)


if __name__ == "__main__":
    unittest.main()

