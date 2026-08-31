import os
import tempfile
import unittest
from unittest.mock import patch

import database
from app import app


class AegisApiTests(unittest.TestCase):
    """Regression tests that use a temporary SQLite database and no live scan."""

    def setUp(self):
        self.original_db_path = database.DB_PATH
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = os.path.join(self.temp_dir.name, "aegis-test.db")
        database.init_db()
        self.client = app.test_client()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def test_dashboard_and_validation(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.client.post("/api/scan", json={"target": "invalid;target"})
        self.assertEqual(response.status_code, 400)

    @patch("app.scan_target")
    def test_persisted_scan_history_details_stats_and_export(self, mock_scan):
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
        }

        scan_response = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        self.assertEqual(scan_response.status_code, 200)
        scan = scan_response.get_json()
        self.assertEqual(scan["overall_risk"], "HIGH")
        self.assertEqual(len(scan["ports"]), 2)
        scan_id = scan["scan_id"]

        history = self.client.get("/api/history").get_json()
        self.assertEqual(history[0]["id"], scan_id)
        self.assertEqual(history[0]["open_port_count"], 2)

        details = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(details.status_code, 200)
        self.assertEqual(details.get_json()["ports"][0]["risk"], "HIGH")
        self.assertEqual(self.client.get("/api/scan/99999").status_code, 404)

        stats = self.client.get("/api/stats").get_json()
        self.assertEqual(stats, {
            "total_scans": 1,
            "total_open_ports": 2,
            "high_risk_count": 1,
            "medium_risk_count": 0,
            "low_risk_count": 1,
        })

        report = self.client.get(f"/api/scan/{scan_id}/export")
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"Target: 127.0.0.1", report.data)
        self.assertIn(b"Port: 21/tcp (open)", report.data)

    def test_malformed_json_and_edge_cases(self):
        """Verify DAST-A01 fix: malformed JSON returns HTTP 400, not 500."""
        # Raw unparseable JSON string
        resp = self.client.post(
            "/api/scan",
            data="{malformed_json",
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["message"], "Invalid JSON format in request body.")

        # Non-dict JSON payload (integer, list, boolean)
        resp_int = self.client.post("/api/scan", data="12345", content_type="application/json")
        self.assertEqual(resp_int.status_code, 400)

        # Missing target field
        resp_empty = self.client.post("/api/scan", json={})
        self.assertEqual(resp_empty.status_code, 400)
        self.assertEqual(resp_empty.get_json()["message"], "Target parameter is required.")

    def test_security_headers_and_server_banner(self):
        """Verify DAST-P01, FINDING-003, and FINDING-010 security headers."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertEqual(resp.headers.get("Server"), "Aegis-Scanner")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))
        self.assertNotIn("fonts.googleapis.com", resp.headers.get("Content-Security-Policy", ""))

        # Verify API cache control
        api_resp = self.client.get("/api/stats")
        self.assertEqual(api_resp.headers.get("Cache-Control"), "no-store")

    def test_secret_key_configured(self):
        """Verify FINDING-002: Flask secret key is set and non-empty."""
        self.assertTrue(bool(app.secret_key))
        self.assertIsInstance(app.secret_key, (str, bytes))

    @patch("app.scan_target")
    def test_rate_limiting_enforcement(self, mock_scan):
        """Verify FINDING-008: Rate limiting returns HTTP 429 upon threshold breach."""
        mock_scan.return_value = {"target": "127.0.0.1", "status": "success", "ports": []}
        statuses = []
        for _ in range(12):
            r = self.client.post("/api/scan", json={"target": "127.0.0.1"})
            statuses.append(r.status_code)

        self.assertIn(429, statuses)
        # Ensure 429 response is sanitized JSON
        resp_429 = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        if resp_429.status_code == 429:
            self.assertIn("Rate limit exceeded", resp_429.get_json()["message"])

    @patch("app.scan_target")
    def test_clear_scan_history(self, mock_scan):
        """Verify Phase 10 feature: DELETE /api/history permanently clears database records."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]
        }
        # Insert a scan
        self.client.post("/api/scan", json={"target": "127.0.0.1"})
        
        # Verify history is populated
        history = self.client.get("/api/history").get_json()
        self.assertEqual(len(history), 1)

        # Delete history via DELETE /api/history
        delete_resp = self.client.delete("/api/history")
        self.assertEqual(delete_resp.status_code, 200)
        self.assertEqual(delete_resp.get_json()["status"], "success")

        # Verify history is now empty
        history_after = self.client.get("/api/history").get_json()
        self.assertEqual(len(history_after), 0)

        # Verify stats are reset to 0
        stats_after = self.client.get("/api/stats").get_json()
        self.assertEqual(stats_after["total_scans"], 0)
        self.assertEqual(stats_after["total_open_ports"], 0)


if __name__ == "__main__":
    unittest.main()


