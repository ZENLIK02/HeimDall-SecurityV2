import unittest

from scripts.generate_300_alert_dataset import generate_dataset as generate_300
from scripts.generate_active_local_dataset import generate_dataset as generate_active


class CombinedFinalDatasetTests(unittest.TestCase):
    def test_combined_final_dataset_size_and_sources(self):
        rows = generate_300(seed=42) + generate_active(seed=42)
        self.assertGreaterEqual(len(rows), 420)
        self.assertEqual(len(rows), 480)
        sources = {row["source"] for row in rows}
        self.assertEqual(sources, {"synthetic_300", "active_local_fixture"})


if __name__ == "__main__":
    unittest.main()
