import unittest

from heimdall.semgrep_ingest import load_semgrep_alerts


class SemgrepIngestTests(unittest.TestCase):
    def test_loads_sample_semgrep_json(self):
        alerts = load_semgrep_alerts("test_data/semgrep-results-sample.json")
        self.assertEqual(len(alerts), 4)
        self.assertEqual(alerts[0].alert_id, "python.flask.security.xss.reflected-xss")
        self.assertEqual(alerts[0].vulnerability_type, "XSS")
        self.assertEqual(alerts[0].severity, "high")
        self.assertIn("request.args", alerts[0].code_snippet)


if __name__ == "__main__":
    unittest.main()
