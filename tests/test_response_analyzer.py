import unittest

from heimdall.pipeline.models import DastResult, ValidationPayload
from heimdall.pipeline.response_analyzer import analyze_response


class ResponseAnalyzerTests(unittest.TestCase):
    def test_confirms_command_marker(self):
        payload = ValidationPayload("Command Injection", "POST", "/ping")
        result = DastResult("confirmed", 200, "HEIMDALL_CMD_PROBE")
        analysis = analyze_response(payload, result)
        self.assertEqual(analysis.status, "confirmed")

    def test_inconclusive_for_business_logic(self):
        payload = ValidationPayload("Business Logic Flaw", "POST", "/coupon")
        result = DastResult("inconclusive", 200, "needs state")
        analysis = analyze_response(payload, result)
        self.assertEqual(analysis.status, "inconclusive")


if __name__ == "__main__":
    unittest.main()

