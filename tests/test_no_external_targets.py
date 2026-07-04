import unittest
from urllib.parse import urlparse

from scripts.generate_active_local_dataset import generate_dataset


class NoExternalTargetsTests(unittest.TestCase):
    def test_active_dataset_uses_only_local_targets(self):
        for alert in generate_dataset():
            target = urlparse(alert["target_base_url"])
            self.assertIn(target.hostname, {"127.0.0.1", "localhost"})
            self.assertNotIn("http://example.invalid", alert["target_base_url"])


if __name__ == "__main__":
    unittest.main()
