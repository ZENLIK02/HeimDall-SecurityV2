import unittest

from heimdall.pipeline.llm_reasoning import validate_llm_output


class LLMReasoningTests(unittest.TestCase):
    def test_validates_structured_output(self):
        output = validate_llm_output(
            {
                "vulnerability_type": "XSS",
                "exploitability": "uncertain",
                "confidence": 0.5,
                "reasoning_summary": "summary",
                "validation_strategy": "dry run",
                "payloads": [],
                "safety_notes": [],
                "recommended_action": "needs_review",
            }
        )
        self.assertEqual(output.exploitability, "uncertain")

    def test_rejects_invalid_confidence(self):
        with self.assertRaises(ValueError):
            validate_llm_output(
                {
                    "vulnerability_type": "XSS",
                    "exploitability": "uncertain",
                    "confidence": 2.0,
                    "reasoning_summary": "summary",
                    "validation_strategy": "dry run",
                    "payloads": [],
                    "safety_notes": [],
                    "recommended_action": "needs_review",
                }
            )


if __name__ == "__main__":
    unittest.main()

