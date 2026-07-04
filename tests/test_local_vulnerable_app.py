import unittest

from local_lab.vulnerable_app.app import app


class LocalVulnerableAppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_sql_fixture_has_vulnerable_and_safe_paths(self):
        vulnerable = self.client.get("/sql/vulnerable", query_string={"username": "alice' OR '1'='1"})
        safe = self.client.get("/sql/safe", query_string={"username": "alice' OR '1'='1"})
        self.assertIn("HEIMDALL_SQLI_MARKER", vulnerable.get_data(as_text=True))
        self.assertNotIn("HEIMDALL_SQLI_MARKER", safe.get_data(as_text=True))

    def test_open_redirect_is_observable_without_following_redirect(self):
        response = self.client.get(
            "/redirect/vulnerable",
            query_string={"next": "http://example.invalid/HEIMDALL_REDIRECT_MARKER"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "http://example.invalid/HEIMDALL_REDIRECT_MARKER")


if __name__ == "__main__":
    unittest.main()
