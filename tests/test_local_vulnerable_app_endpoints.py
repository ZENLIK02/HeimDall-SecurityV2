import unittest

from local_lab.vulnerable_app.app import app


class LocalVulnerableAppEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_required_markers_are_observable(self):
        checks = [
            ("/xss/vulnerable", "GET", {"marker": "HEIMDALL_XSS_MARKER"}, None, "HEIMDALL_XSS_MARKER"),
            ("/sql/vulnerable", "GET", {"username": "alice' OR '1'='1"}, None, "HEIMDALL_SQLI_MARKER"),
            ("/path/vulnerable", "GET", {"file": "../controlled_secret.txt"}, None, "HEIMDALL_PATH_MARKER"),
            ("/cmd/vulnerable", "GET", {"cmd": "fake-date"}, None, "HEIMDALL_CMD_MARKER"),
            ("/ssrf/vulnerable", "GET", {"url": "http://127.0.0.1:5005/internal/metadata"}, None, "HEIMDALL_SSRF_MARKER"),
            ("/idor/vulnerable", "GET", {"object_id": "2002"}, None, "HEIMDALL_IDOR_MARKER"),
            ("/access/vulnerable", "GET", {"role": "user"}, None, "HEIMDALL_ACCESS_MARKER"),
            ("/crypto/vulnerable", "GET", {"value": "heimdall"}, None, "HEIMDALL_CRYPTO_MARKER"),
            ("/secret/vulnerable", "GET", {}, None, "HEIMDALL_SECRET_MARKER"),
            ("/business/vulnerable", "POST", {}, {"coupon": "DOUBLE_APPLY"}, "HEIMDALL_BIZLOGIC_MARKER"),
            ("/deserialize/vulnerable", "POST", {}, "heimdall serialized payload fixture", "HEIMDALL_DESERIALIZATION_MARKER"),
        ]
        for endpoint, method, query, body, marker in checks:
            with self.subTest(endpoint=endpoint):
                if method == "GET":
                    response = self.client.get(endpoint, query_string=query)
                elif isinstance(body, dict):
                    response = self.client.post(endpoint, json=body)
                else:
                    response = self.client.post(endpoint, data=body)
                self.assertIn(marker, response.get_data(as_text=True))

    def test_redirect_marker_uses_location_without_following(self):
        response = self.client.get(
            "/redirect/vulnerable",
            query_string={"next": "http://example.invalid/HEIMDALL_REDIRECT_MARKER"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("HEIMDALL_REDIRECT_MARKER", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
