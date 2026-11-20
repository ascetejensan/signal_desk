"""I verify that my read-only demonstration needs no sign-in or server API key."""
import unittest
from backend.web import app


class PublicDemoTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_readonly_page_opens_without_a_password(self):
        response = self.client.get("/demo")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CTI SENTINEL", response.data)
        self.assertIn(b"read-only", response.data.lower())

    def test_public_snapshot_summary(self):
        response = self.client.get("/api/demo/summary")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["readOnly"])
        self.assertGreaterEqual(body["snapshotEvents"], 1)

    def test_public_snapshot_search(self):
        response = self.client.get("/api/demo/events?page=1")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["readOnly"])
        self.assertLessEqual(len(body["items"]), 15)

    def test_private_intelligence_stays_protected(self):
        response = self.client.post("/api/intel/hash", json={"hash": "a"*64})
        self.assertIn(response.status_code, {401, 503})


if __name__ == "__main__":
    unittest.main()
