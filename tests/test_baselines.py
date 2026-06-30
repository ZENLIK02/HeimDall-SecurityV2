import unittest

from heimdall.evaluation.baselines import SUPPORTED_MODES, run_mode
from heimdall.evaluation.models import Alert


def alert(alert_id, label, snippet="raw = request.args['x']", notes=""):
    return Alert(
        alert_id=alert_id,
        vulnerability_type="SQL Injection",
        severity="high",
        file_path="app.py",
        line_number=1,
        code_snippet=snippet,
        endpoint="/login",
        method="POST",
        parameters={"username": "demo"},
        sast_message="Manual SQL string construction detected.",
        ground_truth_label=label,
        notes=notes,
    )


class BaselineTests(unittest.TestCase):
    def test_all_modes_return_results(self):
        alerts = [
            alert("real", "true_positive"),
            alert("safe", "false_positive", snippet="if not USER_RE.fullmatch(username): abort(400)", notes="Allowlist blocks injection."),
        ]
        for mode in SUPPORTED_MODES:
            with self.subTest(mode=mode):
                results = run_mode(alerts, mode)
                self.assertEqual(len(results), 2)
                self.assertTrue(all(result.mode == mode for result in results))

    def test_rule_based_filtering_dismisses_sanitized_alert(self):
        results = run_mode(
            [alert("safe", "false_positive", snippet="safe = html.escape(value)", notes="Input is escaped before rendering.")],
            "rule_based_filtering",
        )
        self.assertEqual(results[0].prediction, "dismissed")


if __name__ == "__main__":
    unittest.main()
