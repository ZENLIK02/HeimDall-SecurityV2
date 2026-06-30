import json
import tempfile
import unittest
from pathlib import Path

from heimdall.evaluation.dataset_loader import DatasetValidationError, load_alerts_jsonl, normalize_label


class DatasetLoaderTests(unittest.TestCase):
    def test_normalize_label(self):
        self.assertEqual(normalize_label("TP"), "true_positive")
        self.assertEqual(normalize_label("false positive"), "false_positive")
        with self.assertRaises(DatasetValidationError):
            normalize_label("unknown")

    def test_load_valid_and_malformed_rows(self):
        valid = {
            "alert_id": "A-1",
            "vulnerability_type": "XSS",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 1,
            "code_snippet": "x",
            "endpoint": "/",
            "method": "GET",
            "parameters": {},
            "sast_message": "message",
            "ground_truth_label": "true",
            "notes": "note",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "alerts.jsonl"
            path.write_text(json.dumps(valid) + "\nnot-json\n", encoding="utf-8")
            alerts, warnings = load_alerts_jsonl(path)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].ground_truth_label, "true_positive")
        self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()

