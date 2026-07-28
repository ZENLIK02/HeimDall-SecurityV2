import unittest

from heimdall.evaluation.active_local import is_local_url_allowed


class ActiveValidationSafetyTests(unittest.TestCase):
    def test_allows_only_allowlisted_localhost(self):
        allowed = ("http://127.0.0.1:5005", "http://localhost:5005")
        self.assertTrue(is_local_url_allowed("http://127.0.0.1:5005/health", allowed))
        self.assertTrue(is_local_url_allowed("http://localhost:5005/health", allowed))
        self.assertFalse(is_local_url_allowed("https://example.com/health", allowed))
        self.assertFalse(is_local_url_allowed("http://127.0.0.1:8000/health", allowed))
        self.assertFalse(is_local_url_allowed("http://user:pass@127.0.0.1:5005/health", allowed))
        self.assertFalse(is_local_url_allowed("http://127.0.0.1:5005/health#fragment", allowed))
        self.assertFalse(is_local_url_allowed("file:///etc/passwd", allowed))


if __name__ == "__main__":
    unittest.main()
