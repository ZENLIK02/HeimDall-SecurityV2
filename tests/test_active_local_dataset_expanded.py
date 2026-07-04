import unittest
from collections import Counter

from scripts.generate_active_local_dataset import CATEGORIES, TOTAL_ACTIVE_ALERTS, generate_dataset


class ExpandedActiveLocalDatasetTests(unittest.TestCase):
    def test_count_categories_and_seed_reproducibility(self):
        first = generate_dataset(seed=42)
        second = generate_dataset(seed=42)
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(first), 120)
        self.assertEqual(len(first), TOTAL_ACTIVE_ALERTS)
        self.assertEqual(set(Counter(row["vulnerability_type"] for row in first)), set(CATEGORIES))

    def test_needs_review_is_not_hidden(self):
        behaviors = Counter(row["expected_validation_behavior"] for row in generate_dataset())
        self.assertGreater(behaviors["needs_review"], 0)
        self.assertGreater(behaviors["confirmable_active_local"], behaviors["needs_review"])


if __name__ == "__main__":
    unittest.main()
