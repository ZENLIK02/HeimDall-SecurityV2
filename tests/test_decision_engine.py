import unittest

from heimdall.pipeline.decision_engine import decide
from heimdall.pipeline.models import DastResult, LLMReasoningOutput, ResponseAnalysis


class DecisionEngineTests(unittest.TestCase):
    def llm(self, vuln="XSS", confidence=0.8, exploitability="likely_exploitable"):
        return LLMReasoningOutput(vuln, exploitability, confidence, "summary", "strategy", [], [], "validate_with_dast")

    def test_true_positive_decision(self):
        decision = decide(self.llm(), DastResult("confirmed"), ResponseAnalysis("confirmed", "evidence", 0.8))
        self.assertEqual(decision.decision, "True Positive")

    def test_needs_review_when_blocked(self):
        decision = decide(self.llm(), DastResult("blocked", blocked_reason="blocked"), ResponseAnalysis("inconclusive", "blocked", 0.5))
        self.assertEqual(decision.decision, "Needs Review")

    def test_needs_review_low_confidence(self):
        decision = decide(self.llm(confidence=0.2), DastResult("confirmed"), ResponseAnalysis("confirmed", "evidence", 0.8))
        self.assertEqual(decision.decision, "Needs Review")


if __name__ == "__main__":
    unittest.main()
