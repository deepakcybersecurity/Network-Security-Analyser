import os
import tempfile
import unittest
from unittest.mock import patch

import database
from ai.provider import AIProviderError
from app import app, limiter
from command_parser import parse_execution_output, parse_nmap_text_output
from command_registry import (
    COMMAND_REGISTRY,
    get_supported_operations,
    validate_execution_plan,
)
from command_runner import cancel_command_execution
from risk_analyzer import (
    SCORE_WEIGHTS,
    SCORING_DISCLAIMER,
    calculate_security_score,
    get_score_band,
)
from scanner import DEFAULT_PROFILE, SCAN_PROFILES
from service_fingerprints import (
    FINGERPRINT_DISCLAIMER,
    get_generic_fingerprint,
    get_service_fingerprint,
)


class AegisApiTests(unittest.TestCase):
    """Regression tests that use a temporary SQLite database and no live scan."""

    def setUp(self):
        self.original_db_path = database.DB_PATH
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        database.DB_PATH = os.path.join(self.temp_dir.name, "aegis-test.db")
        database.init_db()
        limiter.reset()
        self.client = app.test_client()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

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

    @patch("app.scan_target")
    def test_ai_analysis_generation_and_caching(self, mock_scan):
        """Verify AI Security Analyst generates valid schema output and caches in SQLite."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
        }
        scan_resp = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        self.assertEqual(scan_resp.status_code, 200)
        scan_id = scan_resp.get_json()["scan_id"]

        # 1. Initially no cached analysis
        get_initial = self.client.get(f"/api/ai/analyze/{scan_id}")
        self.assertEqual(get_initial.status_code, 404)

        # 2. Generate analysis via POST
        post_resp = self.client.post(f"/api/ai/analyze/{scan_id}", json={})
        self.assertEqual(post_resp.status_code, 200)
        post_data = post_resp.get_json()
        self.assertEqual(post_data["status"], "success")
        self.assertIn("analysis", post_data)
        analysis = post_data["analysis"]

        # Validate mandatory schema fields
        self.assertIn("summary", analysis)
        self.assertIn("findings", analysis)
        self.assertIn("recommendations", analysis)
        self.assertIn("beginner_explanation", analysis)
        self.assertIn("verification_steps", analysis)
        self.assertEqual(len(analysis["findings"]), 2)

        # Validate findings structure and risk preservation
        ftp_finding = next(f for f in analysis["findings"] if f["port"] == 21)
        https_finding = next(f for f in analysis["findings"] if f["port"] == 443)
        self.assertEqual(ftp_finding["aegis_risk"], "HIGH")
        self.assertEqual(https_finding["aegis_risk"], "LOW")

        # 3. Retrieve cached analysis via GET
        get_cached = self.client.get(f"/api/ai/analyze/{scan_id}")
        self.assertEqual(get_cached.status_code, 200)
        cached_data = get_cached.get_json()
        self.assertTrue(cached_data["cached"])
        self.assertEqual(cached_data["analysis"]["summary"], analysis["summary"])

    def test_ai_analysis_deterministic_risk_enforcement(self):
        """Verify the AI analyzer strictly enforces Aegis deterministic risk levels,
        overriding any attempt to downgrade or manipulate risk classifications."""
        from ai.analyzer import validate_and_enforce_risks

        scan_data = {
            "target": "10.0.0.1",
            "ports": [
                {"port": 21, "service": "ftp", "risk": "HIGH", "reason": "Cleartext FTP"},
                {"port": 80, "service": "http", "risk": "MEDIUM", "reason": "Unencrypted HTTP"},
            ]
        }

        # Simulated hallucinated/manipulated AI output attempting to downgrade risks
        manipulated_ai = {
            "summary": "Everything is safe",
            "findings": [
                {"port": 21, "service": "ftp", "aegis_risk": "LOW", "why_it_matters": "harmless", "security_concern": "none"},
                {"port": 80, "service": "http", "aegis_risk": "LOW", "why_it_matters": "harmless", "security_concern": "none"},
                {"port": 9999, "service": "hallucinated", "aegis_risk": "HIGH", "why_it_matters": "fake", "security_concern": "fake"},
            ],
            "recommendations": ["Do nothing"],
            "beginner_explanation": "Safe building",
            "verification_steps": ["check"],
        }

        validated = validate_and_enforce_risks(manipulated_ai, scan_data)

        # Port 21 MUST be enforced as HIGH (not LOW)
        f_21 = next(f for f in validated["findings"] if f["port"] == 21)
        self.assertEqual(f_21["aegis_risk"], "HIGH")

        # Port 80 MUST be enforced as MEDIUM (not LOW)
        f_80 = next(f for f in validated["findings"] if f["port"] == 80)
        self.assertEqual(f_80["aegis_risk"], "MEDIUM")

        # Hallucinated port 9999 MUST be stripped
        ports_present = [f["port"] for f in validated["findings"]]
        self.assertNotIn(9999, ports_present)

    @patch("app.scan_target")
    def test_ai_analysis_zero_open_ports_and_export(self, mock_scan):
        """Verify AI assessment handles zero-port scans and exports into text report."""
        mock_scan.return_value = {
            "target": "192.168.1.1",
            "status": "success",
            "ports": [],
        }
        scan_resp = self.client.post("/api/scan", json={"target": "192.168.1.1"})
        scan_id = scan_resp.get_json()["scan_id"]

        # Run AI analysis on empty ports scan
        ai_resp = self.client.post(f"/api/ai/analyze/{scan_id}")
        self.assertEqual(ai_resp.status_code, 200)
        data = ai_resp.get_json()["analysis"]
        self.assertEqual(len(data["findings"]), 0)
        self.assertIn("zero open tcp ports", data["summary"].lower())

        # Check that text export now includes AI Security Assessment section
        report = self.client.get(f"/api/scan/{scan_id}/export")
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"AI SECURITY ASSESSMENT", report.data)
        self.assertIn(b"Priority Recommendations:", report.data)

    @patch("ai.analyzer.call_chat_completion")
    @patch("app.scan_target")
    def test_ai_analysis_with_live_provider_mock(self, mock_scan, mock_ai_call):
        """Verify AI assessment flow with mocked live provider output."""
        mock_scan.return_value = {
            "target": "10.10.10.5",
            "status": "success",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            ],
        }
        mock_ai_call.return_value = (
            {
                "summary": "Host exposes SSH remote management.",
                "findings": [
                    {
                        "port": 22,
                        "service": "ssh",
                        "aegis_risk": "MEDIUM",
                        "why_it_matters": "Remote shell access exposed.",
                        "security_concern": "Potential brute force vector.",
                    }
                ],
                "recommendations": ["1. Enforce SSH public key authentication."],
                "beginner_explanation": "SSH is like a secure back door into the server.",
                "verification_steps": ["Run 'nmap -p 22 10.10.10.5' to verify."],
            },
            "gpt-4o-mini"
        )

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key-12345"}):
            scan_resp = self.client.post("/api/scan", json={"target": "10.10.10.5"})
            scan_id = scan_resp.get_json()["scan_id"]

            ai_resp = self.client.post(f"/api/ai/analyze/{scan_id}")
            self.assertEqual(ai_resp.status_code, 200)
            data = ai_resp.get_json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["model"], "gpt-4o-mini")
            self.assertEqual(data["analysis"]["summary"], "Host exposes SSH remote management.")
            self.assertEqual(data["analysis"]["findings"][0]["aegis_risk"], "MEDIUM")

    def test_ai_analysis_404_for_unknown_scan(self):
        """Verify 404 response for non-existent scan ID."""
        resp_post = self.client.post("/api/ai/analyze/88888")
        self.assertEqual(resp_post.status_code, 404)
        resp_get = self.client.get("/api/ai/analyze/88888")
        self.assertEqual(resp_get.status_code, 404)

    def test_visualizations_stats_endpoint(self):
        """Verify GET /api/stats/visualizations aggregates risk distribution, top targets, and activity timeline."""
        # Insert test scans
        database.save_scan_results("192.168.1.10", "HIGH", 2, [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH", "reason": "Cleartext FTP"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "Web server"}
        ], profile_id="quick")
        database.save_scan_results("192.168.1.10", "LOW", 1, [
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "risk": "LOW", "reason": "Secure web"}
        ], profile_id="quick")
        database.save_scan_results("10.0.0.1", "MEDIUM", 1, [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "risk": "MEDIUM", "reason": "SSH access"}
        ], profile_id="quick")

        resp = self.client.get("/api/stats/visualizations")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        # Summary
        self.assertEqual(data["summary"]["total_scans"], 3)
        self.assertEqual(data["summary"]["unique_targets"], 2)
        self.assertEqual(data["summary"]["total_open_ports"], 4)

        # Risk distribution
        self.assertEqual(data["risk_distribution"]["high"], 1)
        self.assertEqual(data["risk_distribution"]["medium"], 1)
        self.assertEqual(data["risk_distribution"]["low"], 2)
        self.assertEqual(data["risk_distribution"]["total"], 4)
        self.assertEqual(data["risk_distribution"]["percentages"]["high"], 25.0)
        self.assertEqual(data["risk_distribution"]["percentages"]["medium"], 25.0)
        self.assertEqual(data["risk_distribution"]["percentages"]["low"], 50.0)

        # Top targets
        self.assertTrue(len(data["top_targets"]) >= 1)
        self.assertEqual(data["top_targets"][0]["target"], "192.168.1.10")
        self.assertEqual(data["top_targets"][0]["scan_count"], 2)

        # Timeline
        self.assertTrue(len(data["activity_timeline"]) >= 1)

    def test_visualizations_empty_database(self):
        """Verify GET /api/stats/visualizations returns graceful empty metrics when no scans exist."""
        resp = self.client.get("/api/stats/visualizations")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["summary"]["total_scans"], 0)
        self.assertEqual(data["summary"]["unique_targets"], 0)
        self.assertEqual(data["summary"]["total_open_ports"], 0)
        self.assertEqual(data["risk_distribution"]["total"], 0)
        self.assertEqual(data["risk_distribution"]["high"], 0)
        self.assertEqual(data["risk_distribution"]["medium"], 0)
        self.assertEqual(data["risk_distribution"]["low"], 0)
        self.assertEqual(data["risk_distribution"]["percentages"]["high"], 0)
        self.assertEqual(data["top_targets"], [])
        self.assertEqual(data["activity_timeline"], [])

    def test_scan_comparison_success_same_target(self):
        """Verify GET /api/scan/compare successfully categorizes exposure diff between two scans of the same target."""
        id_1 = database.save_scan_results("192.168.1.50", "HIGH", 3, [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH", "reason": "Cleartext FTP"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "Standard HTTP"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "OpenSSH 7.4", "risk": "MEDIUM", "reason": "Old SSH"},
        ], profile_id="quick")

        id_2 = database.save_scan_results("192.168.1.50", "LOW", 3, [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "Standard HTTP"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "OpenSSH 8.9", "risk": "MEDIUM", "reason": "Updated SSH"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "risk": "LOW", "reason": "TLS HTTPS"},
        ], profile_id="quick")

        resp = self.client.get(f"/api/scan/compare?base_id={id_1}&target_id={id_2}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["target"], "192.168.1.50")
        self.assertEqual(data["earlier_scan"]["id"], id_1)
        self.assertEqual(data["later_scan"]["id"], id_2)

        # Summary counts
        self.assertEqual(data["counts"]["newly_detected"], 1)
        self.assertEqual(data["counts"]["not_detected"], 1)
        self.assertEqual(data["counts"]["unchanged"], 1)
        self.assertEqual(data["counts"]["changed_service"], 1)

        # 1. Newly detected port 443
        newly = data["newly_detected"]
        self.assertEqual(len(newly), 1)
        self.assertEqual(newly[0]["port"], 443)
        self.assertEqual(newly[0]["risk"], "LOW")
        self.assertIn("remediation", newly[0])

        # 2. Port 21 not detected in later scan (safe wording check)
        missing = data["not_detected"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["port"], 21)
        self.assertEqual(missing[0]["risk"], "HIGH")
        self.assertIn("not detected in Scan", missing[0]["status_note"])
        self.assertNotIn("permanently closed", missing[0]["status_note"].lower())

        # 3. Unchanged port 80
        unchanged = data["unchanged"]
        self.assertEqual(len(unchanged), 1)
        self.assertEqual(unchanged[0]["port"], 80)
        self.assertEqual(unchanged[0]["risk"], "LOW")

        # 4. Changed service port 22
        changed = data["changed_service"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["port"], 22)
        self.assertEqual(changed[0]["earlier_service"], "OpenSSH 7.4")
        self.assertEqual(changed[0]["later_service"], "OpenSSH 8.9")

        # General caveats present
        self.assertTrue(bool(data["caveats"]))

    def test_scan_comparison_mismatched_targets(self):
        """Verify GET /api/scan/compare rejects comparisons across differing targets with HTTP 400."""
        id_1 = database.save_scan_results("192.168.1.1", "LOW", 0, [], profile_id="quick")
        id_2 = database.save_scan_results("10.0.0.1", "LOW", 0, [], profile_id="quick")

        resp = self.client.get(f"/api/scan/compare?base_id={id_1}&target_id={id_2}")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Target mismatch", data["message"])

    def test_scan_comparison_missing_or_invalid_ids(self):
        """Verify GET /api/scan/compare handles invalid, missing, duplicate, and non-existent IDs."""
        # Missing parameters
        self.assertEqual(self.client.get("/api/scan/compare").status_code, 400)
        self.assertEqual(self.client.get("/api/scan/compare?base_id=1").status_code, 400)

        # Non-integer IDs
        self.assertEqual(self.client.get("/api/scan/compare?base_id=abc&target_id=2").status_code, 400)

        # Same scan ID against itself
        self.assertEqual(self.client.get("/api/scan/compare?base_id=1&target_id=1").status_code, 400)

        # Non-existent scan ID (404)
        resp_404 = self.client.get("/api/scan/compare?base_id=99991&target_id=99992")
        self.assertEqual(resp_404.status_code, 404)

    def test_scan_comparison_differing_profiles(self):
        """Verify GET /api/scan/compare flags differing profiles and returns appropriate caveats."""
        id_1 = database.save_scan_results("scanme.nmap.org", "LOW", 0, [], profile_id="quick")
        id_2 = database.save_scan_results("scanme.nmap.org", "LOW", 0, [], profile_id="full")

        resp = self.client.get(f"/api/scan/compare?base_id={id_1}&target_id={id_2}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsNotNone(data["profile_discrepancy"])
        self.assertIn("differing scan profiles", data["profile_discrepancy"])

    def test_scan_comparison_zero_open_ports(self):
        """Verify GET /api/scan/compare handles scans with zero open ports gracefully."""
        id_1 = database.save_scan_results("10.10.10.10", "LOW", 0, [], profile_id="quick")
        id_2 = database.save_scan_results("10.10.10.10", "LOW", 0, [], profile_id="quick")

        resp = self.client.get(f"/api/scan/compare?base_id={id_1}&target_id={id_2}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["counts"]["newly_detected"], 0)
        self.assertEqual(data["counts"]["not_detected"], 0)
        self.assertEqual(data["counts"]["unchanged"], 0)
        self.assertEqual(data["counts"]["changed_service"], 0)
        self.assertEqual(data["newly_detected"], [])
        self.assertEqual(data["not_detected"], [])
        self.assertEqual(data["unchanged"], [])
        self.assertEqual(data["changed_service"], [])

    # =========================================================================
    # PHASE 2: AI SECURITY ANALYST ADVANCED TESTS
    # =========================================================================

    @patch("ai.analyzer.call_chat_completion")
    def test_ai_analysis_caching_and_force_refresh(self, mock_ai_call):
        """Verify AI assessment caching prevents duplicate provider invocations, and force_refresh re-invokes provider."""
        mock_ai_call.return_value = (
            {
                "summary": "Initial AI assessment.",
                "findings": [],
                "recommendations": ["Recommendation 1"],
                "beginner_explanation": "Simple explanation",
                "verification_steps": ["Step 1"],
            },
            "gpt-4o-mini"
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key-cache"}):
            scan_id = database.save_scan_results("192.168.1.100", "LOW", 0, [], profile_id="quick")

            # 1. First POST: Generates assessment, calls provider once
            r1 = self.client.post(f"/api/ai/analyze/{scan_id}", json={})
            self.assertEqual(r1.status_code, 200)
            self.assertFalse(r1.get_json()["cached"])
            self.assertEqual(mock_ai_call.call_count, 1)

            # 2. Second POST (no force_refresh): returns cached, provider count stays 1
            r2 = self.client.post(f"/api/ai/analyze/{scan_id}", json={})
            self.assertEqual(r2.status_code, 200)
            self.assertTrue(r2.get_json()["cached"])
            self.assertEqual(mock_ai_call.call_count, 1)

            # 3. GET request: returns cached, provider count stays 1
            r3 = self.client.get(f"/api/ai/analyze/{scan_id}")
            self.assertEqual(r3.status_code, 200)
            self.assertTrue(r3.get_json()["cached"])
            self.assertEqual(mock_ai_call.call_count, 1)

            # 4. POST with force_refresh=True: re-invokes provider
            mock_ai_call.return_value = (
                {
                    "summary": "Refreshed AI assessment.",
                    "findings": [],
                    "recommendations": ["Updated recommendation"],
                    "beginner_explanation": "Updated explanation",
                    "verification_steps": ["Step 2"],
                },
                "gpt-4o-mini"
            )
            r4 = self.client.post(f"/api/ai/analyze/{scan_id}", json={"force_refresh": True})
            self.assertEqual(r4.status_code, 200)
            self.assertFalse(r4.get_json()["cached"])
            self.assertEqual(mock_ai_call.call_count, 2)
            self.assertEqual(r4.get_json()["analysis"]["summary"], "Refreshed AI assessment.")

    @patch("ai.analyzer.call_chat_completion")
    def test_ai_provider_network_and_timeout_fallback(self, mock_ai_call):
        """Verify AI assessment gracefully falls back to offline heuristics when provider fails or times out."""
        mock_ai_call.side_effect = AIProviderError("Connection timeout while contacting AI provider.")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key-timeout"}):
            scan_id = database.save_scan_results("10.0.0.50", "HIGH", 1, [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH", "reason": "Cleartext FTP"}
            ], profile_id="quick")

            resp = self.client.post(f"/api/ai/analyze/{scan_id}", json={})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()["analysis"]
            self.assertIn("summary", data)
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"][0]["port"], 21)
            self.assertEqual(data["findings"][0]["aegis_risk"], "HIGH")
            self.assertIn("_provider_warning", data)

    def test_ai_provider_invalid_base_url_scheme(self):
        """Verify provider rejects non-HTTP(S) schemes (e.g. file://) and cloud metadata to prevent SSRF."""
        from ai.provider import call_chat_completion
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test", "OPENAI_BASE_URL": "file:///etc"}):
            with self.assertRaises(AIProviderError) as ctx:
                call_chat_completion("system", "user")
            self.assertIn("Invalid OPENAI_BASE_URL scheme", str(ctx.exception))

        # Cloud metadata SSRF blocking
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test", "OPENAI_BASE_URL": "http://169.254.169.254/v1"}):
            with self.assertRaises(AIProviderError) as ctx:
                call_chat_completion("system", "user")
            self.assertIn("cloud metadata", str(ctx.exception).lower())

    def test_ai_analysis_secrets_never_leaked(self):
        """Verify server API keys are never leaked in API responses, error messages, or reports."""
        secret_key_val = "sk-super-secret-production-key-999888777"
        with patch.dict(os.environ, {"OPENAI_API_KEY": secret_key_val}):
            scan_id = database.save_scan_results("127.0.0.1", "LOW", 0, [], profile_id="quick")

            # Successful response
            res_ok = self.client.post(f"/api/ai/analyze/{scan_id}", json={})
            self.assertNotIn(secret_key_val, res_ok.get_data(as_text=True))

            # Error response
            res_err = self.client.post("/api/ai/analyze/99999", json={})
            self.assertNotIn(secret_key_val, res_err.get_data(as_text=True))

            # Report export
            res_rep = self.client.get(f"/api/scan/{scan_id}/export")
            self.assertNotIn(secret_key_val, res_rep.get_data(as_text=True))

    # =========================================================================
    # PHASE 3: SCAN COMPARISON (ALL 12 CASES VERIFIED)
    # =========================================================================

    def test_compare_all_12_edge_cases(self):
        """Comprehensive verification of all 12 required scan comparison scenarios."""
        # Setup scans on target A (192.168.1.10) and target B (10.0.0.5)
        # Scan 1: Baseline target A with ports 80, 22 (OpenSSH 7.4), 21 (FTP)
        s1 = database.save_scan_results("192.168.1.10", "HIGH", 3, [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH", "reason": "FTP"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "OpenSSH 7.4", "risk": "MEDIUM", "reason": "SSH"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "HTTP"}
        ], profile_id="quick")

        # Scan 2: Later target A with ports 80, 22 (OpenSSH 9.0), 443 (HTTPS)
        s2 = database.save_scan_results("192.168.1.10", "LOW", 3, [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "OpenSSH 9.0", "risk": "MEDIUM", "reason": "Updated SSH"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "HTTP"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "risk": "LOW", "reason": "HTTPS"}
        ], profile_id="quick")

        # Scan 3: Target A with zero ports
        s3 = database.save_scan_results("192.168.1.10", "LOW", 0, [], profile_id="quick")

        # Scan 4: Target A with zero ports (second audit)
        s4 = database.save_scan_results("192.168.1.10", "LOW", 0, [], profile_id="quick")

        # Scan 5: Target B (different target)
        s5 = database.save_scan_results("10.0.0.5", "LOW", 1, [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "HTTP"}
        ], profile_id="quick")

        # Scan 6: Target A with full scan profile
        s6 = database.save_scan_results("192.168.1.10", "LOW", 1, [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "LOW", "reason": "HTTP"}
        ], profile_id="all_tcp")

        # Scan 7: Target A with None/missing metadata
        s7 = database.save_scan_results("192.168.1.10", "LOW", 1, [
            {"port": 8080, "protocol": "tcp", "state": None, "service": None, "risk": None, "reason": None}
        ], profile_id="quick")

        # Case 1 & 2 & 3 & 4: Newly detected (443), missing (21), unchanged (80), changed service (22)
        r12 = self.client.get(f"/api/scan/compare?base_id={s1}&target_id={s2}").get_json()
        self.assertEqual(r12["status"], "success")
        self.assertEqual(r12["counts"]["newly_detected"], 1)
        self.assertEqual(r12["counts"]["not_detected"], 1)
        self.assertEqual(r12["counts"]["unchanged"], 1)
        self.assertEqual(r12["counts"]["changed_service"], 1)
        self.assertEqual(r12["newly_detected"][0]["port"], 443)
        self.assertEqual(r12["not_detected"][0]["port"], 21)
        self.assertIn("not detected in Scan", r12["not_detected"][0]["status_note"])
        self.assertEqual(r12["unchanged"][0]["port"], 80)
        self.assertEqual(r12["changed_service"][0]["port"], 22)
        self.assertEqual(r12["changed_service"][0]["earlier_service"], "OpenSSH 7.4")
        self.assertEqual(r12["changed_service"][0]["later_service"], "OpenSSH 9.0")

        # Case 5: Both scans with zero open ports
        r5 = self.client.get(f"/api/scan/compare?base_id={s3}&target_id={s4}").get_json()
        self.assertEqual(r5["status"], "success")
        self.assertEqual(r5["counts"]["newly_detected"], 0)
        self.assertEqual(r5["counts"]["not_detected"], 0)
        self.assertIn("zero open TCP", r5["summary"])

        # Case 6: One scan with ports (s1) and one without (s3)
        # s1 was scanned earlier (3 ports), s3 later (0 ports) -> 3 ports not detected in later scan
        r6 = self.client.get(f"/api/scan/compare?base_id={s3}&target_id={s1}").get_json()
        self.assertEqual(r6["counts"]["newly_detected"], 0)
        self.assertEqual(r6["counts"]["not_detected"], 3)

        # Case 7: Scans of different targets rejected with 400
        r7 = self.client.get(f"/api/scan/compare?base_id={s1}&target_id={s5}")
        self.assertEqual(r7.status_code, 400)
        self.assertIn("Target mismatch", r7.get_json()["message"])

        # Case 8: Invalid, missing, nonexistent scan IDs
        self.assertEqual(self.client.get("/api/scan/compare").status_code, 400)
        self.assertEqual(self.client.get(f"/api/scan/compare?base_id={s1}&target_id=invalid").status_code, 400)
        self.assertEqual(self.client.get(f"/api/scan/compare?base_id={s1}&target_id={s1}").status_code, 400)
        self.assertEqual(self.client.get(f"/api/scan/compare?base_id={s1}&target_id=99999").status_code, 404)

        # Case 9: Different scan profiles (quick vs all_tcp)
        r9 = self.client.get(f"/api/scan/compare?base_id={s1}&target_id={s6}").get_json()
        self.assertIsNotNone(r9["profile_discrepancy"])
        self.assertIn("differing scan profiles", r9["profile_discrepancy"])

        # Case 10: Missing/None service and state metadata handled safely
        r10 = self.client.get(f"/api/scan/compare?base_id={s3}&target_id={s7}").get_json()
        self.assertEqual(r10["status"], "success")
        self.assertEqual(r10["newly_detected"][0]["port"], 8080)
        self.assertEqual(r10["newly_detected"][0]["service"], "unknown")
        self.assertEqual(r10["newly_detected"][0]["state"], "open")

        # Case 11: Reversed order parameter query (base_id=s2 & target_id=s1)
        r11 = self.client.get(f"/api/scan/compare?base_id={s2}&target_id={s1}").get_json()
        # Chronological sort ensures s1 remains earlier_scan and s2 remains later_scan
        self.assertEqual(r11["earlier_scan"]["id"], s1)
        self.assertEqual(r11["later_scan"]["id"], s2)

        # Case 12: Repeated comparisons idempotent and do not modify records
        count_before = len(database.get_scan_history())
        for _ in range(3):
            rep = self.client.get(f"/api/scan/compare?base_id={s1}&target_id={s2}").get_json()
            self.assertEqual(rep["counts"]["newly_detected"], 1)
        count_after = len(database.get_scan_history())
        self.assertEqual(count_before, count_after)

    # =========================================================================
    # PHASE 4: VISUAL RISK DASHBOARD ADVANCED TESTS
    # =========================================================================

    def test_visualizations_risk_distribution_edge_cases(self):
        """Verify donut chart statistics for single-category distributions without NaN or negative values."""
        # Database with only HIGH risk findings
        database.save_scan_results("10.0.0.1", "HIGH", 2, [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH", "reason": "FTP"},
            {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "risk": "HIGH", "reason": "Telnet"},
        ], profile_id="quick")

        data = self.client.get("/api/stats/visualizations").get_json()
        dist = data["risk_distribution"]
        self.assertEqual(dist["high"], 2)
        self.assertEqual(dist["medium"], 0)
        self.assertEqual(dist["low"], 0)
        self.assertEqual(dist["percentages"]["high"], 100.0)
        self.assertEqual(dist["percentages"]["medium"], 0.0)
        self.assertEqual(dist["percentages"]["low"], 0.0)

    def test_visualizations_top_targets_ranking_and_limit(self):
        """Verify top targets chart sorts descending by frequency and caps output at top 5."""
        # Insert 7 different targets with varying frequencies
        for i in range(1, 8):
            target_ip = f"10.0.0.{i}"
            for _ in range(i):  # 10.0.0.7 will have 7 scans, 10.0.0.6 will have 6, etc.
                database.save_scan_results(target_ip, "LOW", 0, [], profile_id="quick")

        data = self.client.get("/api/stats/visualizations").get_json()
        targets = data["top_targets"]
        self.assertEqual(len(targets), 5)  # Strict cap of 5
        self.assertEqual(targets[0]["target"], "10.0.0.7")
        self.assertEqual(targets[0]["scan_count"], 7)
        self.assertEqual(targets[1]["target"], "10.0.0.6")
        self.assertEqual(targets[1]["scan_count"], 6)

    def test_visualizations_activity_timeline_ordering(self):
        """Verify activity timeline groups scans chronologically."""
        database.save_scan_results("192.168.1.1", "LOW", 0, [], profile_id="quick")
        database.save_scan_results("192.168.1.2", "LOW", 0, [], profile_id="quick")

        data = self.client.get("/api/stats/visualizations").get_json()
        timeline = data["activity_timeline"]
        self.assertTrue(len(timeline) >= 1)
        self.assertEqual(timeline[0]["scan_count"], 2)

    # =========================================================================
    # PHASE 6: SECURITY TESTING (INJECTION, XSS, HEADERS, METHODS)
    # =========================================================================

    def test_security_command_injection_and_invalid_targets(self):
        """Verify strict target validation rejects command injection payloads with HTTP 400."""
        payloads = [
            "127.0.0.1; cat /etc/passwd",
            "127.0.0.1 | whoami",
            "$(whoami)",
            "127.0.0.1 && dir",
            "-sS 127.0.0.1",
            "127.0.0.1; reboot",
            "a" * 300,  # Exceeds max length of 253
        ]
        for payload in payloads:
            res = self.client.post("/api/scan", json={"target": payload})
            self.assertEqual(res.status_code, 400, f"Payload '{payload}' was not rejected with 400")

    def test_security_disallowed_http_methods(self):
        """Verify endpoints reject inappropriate HTTP verbs with HTTP 405."""
        self.assertEqual(self.client.put("/api/scan").status_code, 405)
        self.assertEqual(self.client.post("/api/history").status_code, 405)
        self.assertEqual(self.client.put("/api/stats").status_code, 405)
        self.assertEqual(self.client.post("/api/stats/visualizations").status_code, 405)
        self.assertEqual(self.client.delete("/api/scan/1").status_code, 405)

    def test_security_xss_characters_inert_in_db_and_json(self):
        """Verify harmless XSS test vectors are persisted and returned as inert text without executing."""
        xss_target = "192.168.1.200"
        xss_service = '<script>alert("xss")</script>'
        xss_reason = '<img src=x onerror=alert(1)>'

        scan_id = database.save_scan_results(xss_target, "LOW", 1, [
            {"port": 8888, "protocol": "tcp", "state": "open", "service": xss_service, "risk": "LOW", "reason": xss_reason}
        ], profile_id="quick")

        details = self.client.get(f"/api/scan/{scan_id}").get_json()
        port_finding = details["ports"][0]
        self.assertEqual(port_finding["service"], xss_service)
        self.assertEqual(port_finding["reason"], xss_reason)

    # =========================================================================
    # PHASE 7: REGRESSION VERIFICATION
    # =========================================================================

    @patch("app.scan_target")
    def test_regression_full_scan_pipeline_and_export(self, mock_scan):
        """Verify full scan pipeline with deterministic risk calculation and report export."""
        mock_scan.return_value = {
            "target": "10.0.0.99",
            "status": "success",
            "ports": [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
            ]
        }
        res = self.client.post("/api/scan", json={"target": "10.0.0.99", "profile_id": "service_detection"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["overall_risk"], "HIGH")
        self.assertEqual(data["scan_profile"]["profile_id"], "service_detection")
        scan_id = data["scan_id"]

        # Run AI analysis
        ai_res = self.client.post(f"/api/ai/analyze/{scan_id}", json={})
        self.assertEqual(ai_res.status_code, 200)

        # Export report
        rep = self.client.get(f"/api/scan/{scan_id}/export")
        self.assertEqual(rep.status_code, 200)
        self.assertIn(b"AI SECURITY ASSESSMENT", rep.data)
        self.assertIn(b"Quick scan with service detection", rep.data)

        # Clear history cascades to all tables
        del_res = self.client.delete("/api/history")
        self.assertEqual(del_res.status_code, 200)
        self.assertIsNone(database.get_ai_analysis(scan_id))
        self.assertEqual(len(database.get_scan_history()), 0)
        viz = self.client.get("/api/stats/visualizations").get_json()
        self.assertEqual(viz["summary"]["total_scans"], 0)
        self.assertEqual(viz["risk_distribution"]["total"], 0)


    # =========================================================================
    # PHASE 8: TIER 2 FEATURES (PDF, REMEDIATION, CSV, JSON, UNIFIED EXPORT)
    # =========================================================================

    def test_remediation_playbook_all_required_ports(self):
        """Verify deterministic remediation guidance for all specified ports and fallback."""
        from risk_analyzer import analyze_port, get_remediation_guidance

        required_ports = [21, 22, 23, 80, 443, 135, 445, 3306, 3389]
        for port in required_ports:
            guidance = get_remediation_guidance(port, "test-service")
            self.assertIsInstance(guidance, dict)
            for key in ("summary", "steps", "platform", "verification", "warnings"):
                self.assertIn(key, guidance)
                self.assertTrue(guidance[key], f"Missing content for key '{key}' on port {port}")
            self.assertIsInstance(guidance["steps"], list)
            self.assertGreater(len(guidance["steps"]), 0)
            platform = guidance["platform"]
            for os_type in ("linux", "windows", "firewall"):
                self.assertIn(os_type, platform)
                self.assertIsInstance(platform[os_type], list)
                self.assertGreater(len(platform[os_type]), 0)

        # Verify fallback for unspecified port
        fallback_guidance = get_remediation_guidance(9999, "custom-daemon")
        self.assertIn("summary", fallback_guidance)
        self.assertIn("steps", fallback_guidance)
        self.assertIn("platform", fallback_guidance)

        # Verify analyze_port attaches remediation guidance
        finding = analyze_port(21, "ftp")
        self.assertEqual(finding["risk"], "HIGH")
        self.assertIn("remediation", finding)
        self.assertIn("SFTP", finding["remediation"]["summary"])

    def test_csv_formula_injection_sanitization(self):
        """Verify CSV Formula Injection sanitization for dangerous trigger characters."""
        from export_service import sanitize_csv_cell

        self.assertEqual(sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(sanitize_csv_cell("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("-2+3"), "'-2+3")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("\tsneaky"), "'\tsneaky")
        self.assertEqual(sanitize_csv_cell("\rsneaky"), "'\rsneaky")
        self.assertEqual(sanitize_csv_cell("Normal Value"), "Normal Value")
        self.assertEqual(sanitize_csv_cell(None), "")
        self.assertEqual(sanitize_csv_cell(443), "443")

    @patch("app.scan_target")
    def test_unified_export_formats_and_dispatch(self, mock_scan):
        """Verify unified export dispatcher for txt, pdf, csv, and json formats."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
        }

        scan_res = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        self.assertEqual(scan_res.status_code, 200)
        scan_id = scan_res.get_json()["scan_id"]

        # 1. Default (no format specified) -> TXT (backward compatible)
        rep_def = self.client.get(f"/api/scan/{scan_id}/export")
        self.assertEqual(rep_def.status_code, 200)
        self.assertTrue(rep_def.content_type.startswith("text/plain"))
        self.assertIn(f"attachment; filename=aegis-scan-{scan_id}.txt", rep_def.headers.get("Content-Disposition", ""))
        self.assertIn(b"AEGIS PORT SCANNER REPORT", rep_def.data)

        # 2. Explicit format=txt
        rep_txt = self.client.get(f"/api/scan/{scan_id}/export?format=txt")
        self.assertEqual(rep_txt.status_code, 200)
        self.assertTrue(rep_txt.content_type.startswith("text/plain"))
        self.assertIn(b"Port: 21/tcp (open)", rep_txt.data)

        # 3. Explicit format=pdf
        rep_pdf = self.client.get(f"/api/scan/{scan_id}/export?format=pdf")
        self.assertEqual(rep_pdf.status_code, 200)
        self.assertEqual(rep_pdf.content_type, "application/pdf")
        self.assertIn(f"attachment; filename=aegis-scan-{scan_id}.pdf", rep_pdf.headers.get("Content-Disposition", ""))
        self.assertTrue(rep_pdf.data.startswith(b"%PDF-"))
        self.assertGreater(len(rep_pdf.data), 1000)

        # 4. Explicit format=csv
        rep_csv = self.client.get(f"/api/scan/{scan_id}/export?format=csv")
        self.assertEqual(rep_csv.status_code, 200)
        self.assertTrue(rep_csv.content_type.startswith("text/csv"))
        self.assertIn(f"attachment; filename=aegis-scan-{scan_id}.csv", rep_csv.headers.get("Content-Disposition", ""))
        csv_text = rep_csv.data.decode("utf-8")
        self.assertIn("Scan_ID,Target,Scan_Time,Overall_Risk", csv_text)
        self.assertIn("ftp", csv_text)
        self.assertIn("http", csv_text)
        self.assertIn("https", csv_text)

        # 5. Explicit format=json
        rep_json = self.client.get(f"/api/scan/{scan_id}/export?format=json")
        self.assertEqual(rep_json.status_code, 200)
        self.assertTrue(rep_json.content_type.startswith("application/json"))
        self.assertIn(f"attachment; filename=aegis-scan-{scan_id}.json", rep_json.headers.get("Content-Disposition", ""))
        json_payload = rep_json.get_json()
        self.assertEqual(json_payload["schema_version"], "1.0")
        self.assertEqual(json_payload["scan_id"], scan_id)
        self.assertEqual(json_payload["target"], "127.0.0.1")
        self.assertEqual(json_payload["overall_risk"], "HIGH")
        self.assertEqual(len(json_payload["ports"]), 3)
        self.assertIn("remediation", json_payload["ports"][0])
        self.assertIn("summary", json_payload["ports"][0]["remediation"])

        # 6. Unsupported format -> 400 Bad Request
        rep_bad = self.client.get(f"/api/scan/{scan_id}/export?format=xml")
        self.assertEqual(rep_bad.status_code, 400)
        self.assertIn("Unsupported export format", rep_bad.get_json()["message"])

        # 7. Non-existent scan -> 404 Not Found
        rep_nf = self.client.get("/api/scan/99999/export?format=pdf")
        self.assertEqual(rep_nf.status_code, 404)

    @patch("app.scan_target")
    def test_pdf_export_with_cached_ai_assessment(self, mock_scan):
        """Verify PDF export embeds cached AI security analysis seamlessly."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            ],
        }

        scan_res = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        scan_id = scan_res.get_json()["scan_id"]

        # Cache artificial AI analysis
        fake_ai = {
            "summary": "SSH daemon detected on default port 22.",
            "findings": [
                {"port": 22, "service": "ssh", "risk": "MEDIUM", "explanation": "Exposed SSH."}
            ],
            "recommendations": [
                "1. Enforce public-key authentication.",
                "2. Disable PermitRootLogin in sshd_config."
            ],
            "beginner_explanation": "SSH allows remote terminal login. Guard against brute force attacks."
        }
        database.save_ai_analysis(scan_id, fake_ai, model="gpt-4o-mini")

        rep_pdf = self.client.get(f"/api/scan/{scan_id}/export?format=pdf")
        self.assertEqual(rep_pdf.status_code, 200)
        self.assertTrue(rep_pdf.data.startswith(b"%PDF-"))
        self.assertGreater(len(rep_pdf.data), 2000)

        # Verify JSON export includes the AI analysis
        rep_json = self.client.get(f"/api/scan/{scan_id}/export?format=json")
        self.assertEqual(rep_json.status_code, 200)
        data = rep_json.get_json()
        self.assertIsNotNone(data["ai_analysis"])
        self.assertEqual(data["ai_analysis"]["model"], "gpt-4o-mini")
        self.assertEqual(len(data["ai_analysis"]["analysis"]["recommendations"]), 2)

    @patch("app.scan_target")
    def test_exports_zero_open_ports(self, mock_scan):
        """Verify all export formats handle scans with zero open TCP ports gracefully."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [],
        }

        scan_res = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        scan_id = scan_res.get_json()["scan_id"]

        # TXT
        rep_txt = self.client.get(f"/api/scan/{scan_id}/export?format=txt")
        self.assertEqual(rep_txt.status_code, 200)
        self.assertIn(b"No open TCP ports were recorded.", rep_txt.data)

        # PDF
        rep_pdf = self.client.get(f"/api/scan/{scan_id}/export?format=pdf")
        self.assertEqual(rep_pdf.status_code, 200)
        self.assertTrue(rep_pdf.data.startswith(b"%PDF-"))

        # CSV
        rep_csv = self.client.get(f"/api/scan/{scan_id}/export?format=csv")
        self.assertEqual(rep_csv.status_code, 200)
        csv_text = rep_csv.data.decode("utf-8")
        self.assertIn("No open TCP ports detected.", csv_text)

        # JSON
        rep_json = self.client.get(f"/api/scan/{scan_id}/export?format=json")
        self.assertEqual(rep_json.status_code, 200)
        data = rep_json.get_json()
        self.assertEqual(data["open_port_count"], 0)
        self.assertEqual(data["ports"], [])

    @patch("app.scan_target")
    def test_csv_export_formula_injection_defense(self, mock_scan):
        """Verify CSV export sanitizes malicious formula payload in target or service name."""
        mock_scan.return_value = {
            "target": "=cmd|' /C calc'!A0",
            "status": "success",
            "ports": [
                {"port": 80, "protocol": "tcp", "state": "open", "service": "+malicious_service"},
            ],
        }

        # Save directly to database to bypass input validation and test export defense in depth
        scan_id = database.save_scan_results(
            target="=cmd|' /C calc'!A0",
            overall_risk="MEDIUM",
            open_port_count=1,
            ports=[
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "+malicious_service",
                    "risk": "MEDIUM",
                    "reason": "-formula_reason"
                }
            ],
            profile_id="quick"
        )

        rep_csv = self.client.get(f"/api/scan/{scan_id}/export?format=csv")
        self.assertEqual(rep_csv.status_code, 200)
        csv_text = rep_csv.data.decode("utf-8")

        # Must have leading single quotes protecting against Excel/Calc execution
        self.assertIn("'=cmd|' /C calc'!A0", csv_text)
        self.assertIn("'+malicious_service", csv_text)
        self.assertIn("'-formula_reason", csv_text)

    def test_service_fingerprints_knowledge_base_ports(self):
        """Verify static knowledge base coverage for all required Tier 3 ports and caveats."""
        required_ports = [21, 22, 23, 80, 443, 135, 445, 3306, 3389]
        required_fields = [
            "service_name", "display_name", "category", "description",
            "typical_use", "common_security_concerns", "associated_attacks",
            "public_exposure_guidance", "defensive_recommendations",
            "references", "knowledge_limitations", "identification_method", "disclaimer"
        ]

        for port in required_ports:
            card = get_service_fingerprint(port, profile_id="quick", deterministic_risk="LOW")
            self.assertIsInstance(card, dict, f"Port {port} card must be a dict")
            for field in required_fields:
                self.assertIn(field, card, f"Port {port} card must contain '{field}'")
                if field == "references":
                    self.assertIsInstance(card[field], list)
                    self.assertGreater(len(card[field]), 0, f"Port {port} must have at least one reference")
                    for ref in card[field]:
                        self.assertIn("title", ref)
                        self.assertIn("url", ref)
                        self.assertTrue(ref["url"].startswith("http"), f"Reference URL in port {port} must be http(s)")
                elif field == "defensive_recommendations":
                    self.assertIsInstance(card[field], list)
                    self.assertGreater(len(card[field]), 0)
                else:
                    self.assertTrue(bool(card[field]), f"Port {port} '{field}' must not be empty")

        # Specific SMB (445) caveat check: EternalBlue / MS17-010 mentioned only with explicit caveat
        smb_card = get_service_fingerprint(445)
        self.assertIn("EternalBlue", smb_card["associated_attacks"])
        self.assertIn("does not establish that a system is vulnerable", smb_card["associated_attacks"].lower())
        self.assertEqual(smb_card["disclaimer"], FINGERPRINT_DISCLAIMER)

    def test_service_fingerprint_generic_fallback_and_profiles(self):
        """Verify unclassified ports fallback gracefully and scan profiles set appropriate identification method."""
        # Unclassified port
        card = get_service_fingerprint(9999, service="custom-daemon", profile_id="quick")
        self.assertEqual(card["category"], "Unclassified Network Service")
        self.assertIn("9999", card["display_name"])
        self.assertIn("custom-daemon", card["description"])
        self.assertIn("Inferred from standard port assignment", card["identification_method"])

        # Service detection profile
        card_sd = get_service_fingerprint(22, service="ssh", profile_id="service_detection")
        self.assertIn("Service Version Detection (Nmap Probe)", card_sd["identification_method"])

        # Comprehensive profile
        card_comp = get_service_fingerprint(80, service="http", profile_id="comprehensive")
        self.assertIn("Service Version Detection (Nmap Probe)", card_comp["identification_method"])

        # Direct generic fingerprint function
        generic = get_generic_fingerprint(8080, "http-proxy")
        self.assertEqual(generic["service_name"], "http-proxy")
        self.assertIn("8080", generic["display_name"])
        self.assertEqual(generic["disclaimer"], FINGERPRINT_DISCLAIMER)

    def test_security_score_calculation_weights_and_bands(self):
        """Verify deterministic Security Score calculation, weight penalties, deduplication, and bands."""
        # 1. Zero open ports -> 100/100, GOOD
        score_zero = calculate_security_score([], scan_status="success")
        self.assertTrue(score_zero["available"])
        self.assertEqual(score_zero["score"], 100)
        self.assertEqual(score_zero["label"], "GOOD")
        self.assertEqual(score_zero["total_deduction"], 0)
        self.assertEqual(len(score_zero["deductions"]), 0)
        self.assertEqual(score_zero["disclaimer"], SCORING_DISCLAIMER)

        # 2. Single HIGH risk port (-25) -> 75/100, FAIR
        ports_high = [{"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH"}]
        score_high = calculate_security_score(ports_high, scan_status="success")
        self.assertEqual(score_high["score"], 75)
        self.assertEqual(score_high["label"], "FAIR")
        self.assertEqual(score_high["total_deduction"], 25)

        # 3. Single MEDIUM risk port (-10) -> 90/100, GOOD
        ports_med = [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "MEDIUM"}]
        score_med = calculate_security_score(ports_med, scan_status="success")
        self.assertEqual(score_med["score"], 90)
        self.assertEqual(score_med["label"], "GOOD")
        self.assertEqual(score_med["total_deduction"], 10)

        # 4. Single LOW risk port (-3) -> 97/100, GOOD
        ports_low = [{"port": 443, "protocol": "tcp", "state": "open", "service": "https", "risk": "LOW"}]
        score_low = calculate_security_score(ports_low, scan_status="success")
        self.assertEqual(score_low["score"], 97)
        self.assertEqual(score_low["label"], "GOOD")
        self.assertEqual(score_low["total_deduction"], 3)

        # 5. Mixed: 1 HIGH (-25), 1 MED (-10), 1 LOW (-3) -> 100 - 38 = 62, NEEDS IMPROVEMENT
        ports_mixed = [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "MEDIUM"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "risk": "LOW"},
        ]
        score_mixed = calculate_security_score(ports_mixed, scan_status="success")
        self.assertEqual(score_mixed["score"], 62)
        self.assertEqual(score_mixed["label"], "NEEDS IMPROVEMENT")
        self.assertEqual(score_mixed["total_deduction"], 38)
        self.assertEqual(len(score_mixed["deductions"]), 3)

        # 6. Bounding at 0: 5 HIGH ports = -125 deduction -> clamped to 0, CRITICAL
        ports_overflow = [
            {"port": 21 + i, "protocol": "tcp", "state": "open", "service": "srv", "risk": "HIGH"}
            for i in range(5)
        ]
        score_overflow = calculate_security_score(ports_overflow, scan_status="success")
        self.assertEqual(score_overflow["score"], 0)
        self.assertEqual(score_overflow["label"], "CRITICAL")
        self.assertEqual(score_overflow["total_deduction"], 125)

        # 7. Deduplication by protocol:port: duplicate findings must not double count
        ports_duplicate = [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH"},
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "risk": "HIGH"},
        ]
        score_dup = calculate_security_score(ports_duplicate, scan_status="success")
        self.assertEqual(score_dup["score"], 75)
        self.assertEqual(score_dup["total_deduction"], 25)
        self.assertEqual(len(score_dup["deductions"]), 1)

        # 8. State filtering: closed/filtered ports do not deduct
        ports_closed = [
            {"port": 21, "protocol": "tcp", "state": "closed", "service": "ftp", "risk": "HIGH"},
            {"port": 80, "protocol": "tcp", "state": "filtered", "service": "http", "risk": "MEDIUM"},
        ]
        score_closed = calculate_security_score(ports_closed, scan_status="success")
        self.assertEqual(score_closed["score"], 100)
        self.assertEqual(score_closed["total_deduction"], 0)

        # 9. Score band thresholds verification
        self.assertEqual(get_score_band(100), "GOOD")
        self.assertEqual(get_score_band(90), "GOOD")
        self.assertEqual(get_score_band(89), "FAIR")
        self.assertEqual(get_score_band(75), "FAIR")
        self.assertEqual(get_score_band(74), "NEEDS IMPROVEMENT")
        self.assertEqual(get_score_band(50), "NEEDS IMPROVEMENT")
        self.assertEqual(get_score_band(49), "POOR")
        self.assertEqual(get_score_band(25), "POOR")
        self.assertEqual(get_score_band(24), "CRITICAL")
        self.assertEqual(get_score_band(0), "CRITICAL")

        # 10. Failed / incomplete scan handling
        score_failed = calculate_security_score([], scan_status="failed")
        self.assertFalse(score_failed["available"])
        self.assertIsNone(score_failed["score"])
        self.assertEqual(score_failed["label"], "UNAVAILABLE")

    @patch("app.scan_target")
    def test_security_score_and_fingerprints_api_integration(self, mock_scan):
        """Verify POST /api/scan and GET /api/scan/<id> return Security Score and Service Fingerprints."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
        }

        # 1. POST /api/scan
        res = self.client.post("/api/scan", json={"target": "127.0.0.1", "profile_id": "quick"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Check security_score object
        self.assertIn("security_score", data)
        score_obj = data["security_score"]
        self.assertTrue(score_obj["available"])
        self.assertEqual(score_obj["score"], 72)  # 100 - 25 (HIGH) - 3 (LOW) = 72
        self.assertEqual(score_obj["label"], "NEEDS IMPROVEMENT")
        self.assertEqual(score_obj["total_deduction"], 28)

        # Check fingerprint on ports
        self.assertEqual(len(data["ports"]), 2)
        p21 = next(p for p in data["ports"] if p["port"] == 21)
        self.assertIn("fingerprint", p21)
        self.assertEqual(p21["fingerprint"]["service_name"], "ftp")
        self.assertIn("RFC 959", str(p21["fingerprint"]["references"]))

        p443 = next(p for p in data["ports"] if p["port"] == 443)
        self.assertIn("fingerprint", p443)
        self.assertEqual(p443["fingerprint"]["service_name"], "https")

        # 2. GET /api/scan/<id>
        scan_id = data["scan_id"]
        res_get = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.get_json()
        self.assertIn("security_score", get_data)
        self.assertEqual(get_data["security_score"]["score"], 72)
        p21_get = next(p for p in get_data["ports"] if p["port"] == 21)
        self.assertIn("fingerprint", p21_get)
        self.assertEqual(p21_get["fingerprint"]["service_name"], "ftp")

    @patch("app.scan_target")
    def test_security_score_comparison_delta_and_interpretation(self, mock_scan):
        """Verify GET /api/scan/compare attaches security_score and computes correct score_delta."""
        # Create scan 1: earlier scan with port 21 (HIGH, -25) and port 80 (MED, -10) -> score 65
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            ],
        }
        res1 = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        id1 = res1.get_json()["scan_id"]

        # Create scan 2: later scan with port 443 (LOW, -3) -> score 97
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
        }
        res2 = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        id2 = res2.get_json()["scan_id"]

        # Execute comparison
        comp_res = self.client.get(f"/api/scan/compare?base_id={id1}&target_id={id2}")
        self.assertEqual(comp_res.status_code, 200)
        comp_data = comp_res.get_json()

        earlier_score = comp_data["earlier_scan"]["security_score"]
        later_score = comp_data["later_scan"]["security_score"]
        self.assertEqual(earlier_score["score"], 65)
        self.assertEqual(later_score["score"], 97)

        score_comp = comp_data["security_score_comparison"]
        self.assertEqual(score_comp["score_delta"], 32)  # 97 - 65 = +32
        self.assertIn("Score increased by +32 points", score_comp["interpretation"])
        self.assertIn("reduced exposure", score_comp["interpretation"].lower())

    @patch("app.scan_target")
    def test_exports_tier3_integration(self, mock_scan):
        """Verify TXT, PDF, CSV, and JSON exports contain deterministic Security Score and Service Fingerprints."""
        mock_scan.return_value = {
            "target": "127.0.0.1",
            "status": "success",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            ],
        }
        res = self.client.post("/api/scan", json={"target": "127.0.0.1"})
        scan_id = res.get_json()["scan_id"]

        # 1. TXT export
        txt_res = self.client.get(f"/api/scan/{scan_id}/export?format=txt")
        self.assertEqual(txt_res.status_code, 200)
        txt_content = txt_res.data.decode("utf-8")
        self.assertIn("SECURITY SCORE BREAKDOWN", txt_content)
        self.assertIn("Score: 80/100 (FAIR)", txt_content)  # 100 - 10 (SSH MED) - 10 (HTTP MED) = 80
        self.assertIn("Disclaimer: Aegis Security Score is a deterministic exposure heuristic", txt_content)

        # 2. CSV export
        csv_res = self.client.get(f"/api/scan/{scan_id}/export?format=csv")
        self.assertEqual(csv_res.status_code, 200)
        csv_content = csv_res.data.decode("utf-8")
        self.assertIn("Security_Score", csv_content)
        self.assertIn("Security_Score_Label", csv_content)
        self.assertIn("80", csv_content)
        self.assertIn("FAIR", csv_content)

        # 3. JSON export
        json_res = self.client.get(f"/api/scan/{scan_id}/export?format=json")
        self.assertEqual(json_res.status_code, 200)
        json_data = json_res.get_json()
        self.assertIn("security_score", json_data)
        self.assertEqual(json_data["security_score"]["score"], 80)
        self.assertEqual(json_data["security_score"]["label"], "FAIR")
        self.assertIn("deductions", json_data["security_score"])
        self.assertEqual(len(json_data["ports"]), 2)
        for p in json_data["ports"]:
            self.assertIn("fingerprint", p)
            self.assertIn("description", p["fingerprint"])

        # 4. PDF export
        pdf_res = self.client.get(f"/api/scan/{scan_id}/export?format=pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertTrue(pdf_res.data.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_res.data), 1000)

    def test_default_scanner_unmodified(self):
        """Verify Requirement 1: The default scanner remains unchanged (-sT -F) without -A, -T4, or -p-."""
        self.assertEqual(DEFAULT_PROFILE, "quick")
        quick_profile = SCAN_PROFILES.get("quick")
        self.assertIsNotNone(quick_profile)
        args = quick_profile["arguments"]
        self.assertEqual(args, "-sT -F")
        self.assertNotIn("-A", args)
        self.assertNotIn("-T4", args)
        self.assertNotIn("-p-", args)

    def test_copilot_command_registry_and_plan_validation(self):
        """Verify command registry defines at least 7 operations and strictly validates execution plans."""
        # 1. Minimum 7 approved operations
        self.assertGreaterEqual(len(COMMAND_REGISTRY), 7)
        required_ops = [
            "nmap_quick",
            "nmap_common_tcp",
            "nmap_all_tcp",
            "nmap_service_detection",
            "nmap_full_tcp_detailed",
            "http_service_check",
            "dns_reverse_lookup",
        ]
        for op in required_ops:
            self.assertIn(op, COMMAND_REGISTRY)
            entry = COMMAND_REGISTRY[op]
            self.assertIn("tool", entry)
            self.assertIn("purpose", entry)
            self.assertIn("arguments_explanation", entry)
            self.assertIn("expected_output", entry)
            self.assertIn("performance_considerations", entry)
            self.assertIn("operational_impact", entry)
            self.assertIn("prerequisites", entry)
            self.assertIn("safety_warnings", entry)

        # 2. Valid plan passes validation
        valid_plan = {
            "operation_id": "nmap_service_detection",
            "target": "127.0.0.1"
        }
        is_valid, validated, err = validate_execution_plan(valid_plan, "127.0.0.1")
        self.assertTrue(is_valid)
        self.assertIsNotNone(validated)
        self.assertIsNone(err)
        self.assertEqual(validated["operation_id"], "nmap_service_detection")
        self.assertEqual(validated["target"], "127.0.0.1")

        # 3. Unapproved operation rejected
        invalid_op_plan = {
            "operation_id": "unapproved_custom_exploit",
            "target": "127.0.0.1"
        }
        is_valid, _, err = validate_execution_plan(invalid_op_plan, "127.0.0.1")
        self.assertFalse(is_valid)
        self.assertIn("not in the approved", err)

        # 4. Command injection in target rejected
        injection_plan = {
            "operation_id": "nmap_quick",
            "target": "127.0.0.1; rm -rf /"
        }
        is_valid, _, err = validate_execution_plan(injection_plan, "127.0.0.1; rm -rf /")
        self.assertFalse(is_valid)
        self.assertIn("invalid characters", err)

        # 5. Dangerous prefix/suffix rejected
        flag_injection_plan = {
            "operation_id": "nmap_quick",
            "target": "--script=vuln"
        }
        is_valid, _, err = validate_execution_plan(flag_injection_plan, "--script=vuln")
        self.assertFalse(is_valid)
        self.assertIn("cannot start with hyphen", err)

    def test_copilot_command_parser(self):
        """Verify Nmap text output and diagnostic outputs are parsed into structured findings with deterministic risk."""
        sample_nmap = """
Starting Nmap 7.92 ( https://nmap.org ) at 2026-10-22 10:00 UTC
Nmap scan report for 127.0.0.1
Host is up (0.00010s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  https   Apache httpd 2.4.41 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.15 seconds
"""
        parsed_ports = parse_nmap_text_output(sample_nmap, target="127.0.0.1")
        self.assertEqual(len(parsed_ports), 3)

        p22 = next(p for p in parsed_ports if p["port"] == 22)
        self.assertEqual(p22["service"], "ssh")
        self.assertIn("OpenSSH", p22["version"])
        self.assertEqual(p22["risk"], "MEDIUM")  # Deterministic risk analyzer

        p80 = next(p for p in parsed_ports if p["port"] == 80)
        self.assertEqual(p80["service"], "http")
        self.assertEqual(p80["risk"], "MEDIUM")

        # Full execution output parsing
        full_parsed = parse_execution_output("nmap_service_detection", "127.0.0.1", sample_nmap)
        self.assertEqual(full_parsed["total_open_ports"], 3)
        self.assertIn("fingerprint", full_parsed["findings"][0])

    def test_copilot_api_operations_endpoint(self):
        """Verify GET /api/copilot/operations returns all registered operations with documentation."""
        res = self.client.get("/api/copilot/operations")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["count"], 7)
        self.assertTrue(len(data["operations"]) >= 7)

        op_ids = [op["operation_id"] for op in data["operations"]]
        self.assertIn("nmap_full_tcp_detailed", op_ids)
        self.assertIn("http_service_check", op_ids)
        self.assertIn("dns_reverse_lookup", op_ids)

    def test_copilot_chat_natural_language_and_offline_heuristic(self):
        """Verify POST /api/copilot/chat maps natural language queries to command cards and fallback explanations."""
        # 1. Full scan request -> nmap_full_tcp_detailed
        res1 = self.client.post("/api/copilot/chat", json={
            "message": "Scan all TCP ports on my authorized lab machine with deep detection (-A -T4 -p-).",
            "target": "127.0.0.1"
        })
        self.assertEqual(res1.status_code, 200)
        data1 = res1.get_json()
        self.assertEqual(data1["status"], "success")
        self.assertIn("conversation_id", data1)
        self.assertIsNotNone(data1.get("suggested_command"))
        cmd1 = data1["suggested_command"]
        self.assertEqual(cmd1["operation"], "nmap_full_tcp_detailed")
        self.assertIn("-A", cmd1["command_string"])
        self.assertIn("-T4", cmd1["command_string"])
        self.assertIn("-p-", cmd1["command_string"])
        self.assertIn("-A", cmd1["arguments_breakdown"])
        self.assertIn("-T4", cmd1["arguments_breakdown"])
        self.assertIn("-p-", cmd1["arguments_breakdown"])
        self.assertIn("safety_warning", cmd1)

        conv_id = data1["conversation_id"]

        # 2. Service detection request continuing same conversation
        res2 = self.client.post("/api/copilot/chat", json={
            "message": "Use Nmap to identify service versions on top 100 ports.",
            "conversation_id": conv_id,
            "target": "127.0.0.1"
        })
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertEqual(data2["conversation_id"], conv_id)
        cmd2 = data2["suggested_command"]
        self.assertEqual(cmd2["operation"], "nmap_service_detection")
        self.assertIn("-sV", cmd2["command_string"])

        # 3. Web services check request
        res3 = self.client.post("/api/copilot/chat", json={
            "message": "Audit web services and inspect HTTP response headers on this IP.",
            "target": "127.0.0.1"
        })
        self.assertEqual(res3.status_code, 200)
        data3 = res3.get_json()
        cmd3 = data3["suggested_command"]
        self.assertEqual(cmd3["operation"], "http_service_check")
        self.assertEqual(cmd3["tool"], "http_check")

        # 4. Explain risks without generating command
        res4 = self.client.post("/api/copilot/chat", json={
            "message": "Explain the risks associated with these open ports and suggest a next step.",
            "target": "127.0.0.1"
        })
        self.assertEqual(res4.status_code, 200)
        data4 = res4.get_json()
        self.assertTrue(len(data4["reply"]) > 50)
        self.assertIn("risk", data4["reply"].lower())

    def test_copilot_execute_security_controls_and_confirmation(self):
        """Verify POST /api/copilot/execute enforces confirmation, target validation, and scope matching."""
        valid_plan = {
            "operation_id": "dns_reverse_lookup",
            "target": "127.0.0.1"
        }

        # 1. Rejects unconfirmed execution (Requirement 4C)
        res_unconfirmed = self.client.post("/api/copilot/execute", json={
            "execution_plan": valid_plan,
            "confirmed": False
        })
        self.assertEqual(res_unconfirmed.status_code, 400)
        self.assertIn("confirmation is required", res_unconfirmed.get_json()["message"].lower())

        # 2. Rejects invalid injection target
        res_injection = self.client.post("/api/copilot/execute", json={
            "execution_plan": {
                "operation_id": "dns_reverse_lookup",
                "target": "127.0.0.1; whoami"
            },
            "confirmed": True
        })
        self.assertEqual(res_injection.status_code, 400)
        self.assertIn("Target validation failed", res_injection.get_json()["message"])

        # 3. Rejects target scope mismatch against linked scan
        scan_id = database.save_scan_results("192.168.1.50", "LOW", 0, [], "quick")
        res_mismatch = self.client.post("/api/copilot/execute", json={
            "execution_plan": {
                "operation_id": "dns_reverse_lookup",
                "target": "127.0.0.1"
            },
            "scan_id": scan_id,
            "confirmed": True
        })
        self.assertEqual(res_mismatch.status_code, 400)
        self.assertIn("Scope mismatch", res_mismatch.get_json()["message"])

        # 4. Valid execution dispatch
        res_ok = self.client.post("/api/copilot/execute", json={
            "execution_plan": valid_plan,
            "confirmed": True
        })
        self.assertEqual(res_ok.status_code, 202)
        ok_data = res_ok.get_json()
        self.assertEqual(ok_data["status"], "started")
        exec_id = ok_data["execution_id"]
        self.assertIsInstance(exec_id, int)

        # 5. Retrieve execution status
        res_status = self.client.get(f"/api/copilot/execution/{exec_id}")
        self.assertEqual(res_status.status_code, 200)
        st_data = res_status.get_json()
        self.assertEqual(st_data["id"], exec_id)
        self.assertEqual(st_data["operation_id"], "dns_reverse_lookup")

        # 6. Cancellation endpoint
        res_cancel = self.client.post(f"/api/copilot/execution/{exec_id}/cancel")
        self.assertEqual(res_cancel.status_code, 200)

    def test_copilot_report_integration_pdf_csv_json_txt(self):
        """Verify additional findings from Copilot commands integrate into TXT, CSV, JSON, and PDF reports."""
        # 1. Create base scan
        scan_id = database.save_scan_results("127.0.0.1", "MEDIUM", 1, [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "MEDIUM"}
        ], "quick")

        # 2. Add an executed Copilot command linked to this scan with additional findings
        exec_id = database.create_command_execution(
            tool="nmap",
            operation_id="nmap_service_detection",
            command_str="nmap -sT -sV -F 127.0.0.1",
            arguments=["-sT", "-sV", "-F"],
            target="127.0.0.1",
            scan_id=scan_id
        )
        database.update_command_execution(
            exec_id,
            status="completed",
            raw_output="PORT 80/tcp open http Apache/2.4.41\nPORT 8080/tcp open http-proxy Werkzeug/2.0.1",
            parsed_findings={
                "summary": {"open_ports_count": 2},
                "findings": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "Apache/2.4.41",
                        "risk": "MEDIUM",
                        "fingerprint": {"service_name": "http"}
                    },
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http-proxy",
                        "version": "Werkzeug/2.0.1",
                        "risk": "MEDIUM",
                        "fingerprint": {"service_name": "http-proxy"}
                    }
                ],
                "web_observations": {
                    "http_service_detected": True,
                    "server_header": "Werkzeug/2.0.1",
                    "html_title": "Aegis Diagnostic Portal"
                }
            },
            ai_analysis={
                "explanation": "Detected secondary HTTP diagnostic proxy on port 8080.",
                "confidence": "HIGH",
                "recommendations": ["Restrict port 8080 to localhost only."]
            }
        )

        # 3. TXT Export
        txt_res = self.client.get(f"/api/scan/{scan_id}/export?format=txt")
        self.assertEqual(txt_res.status_code, 200)
        txt = txt_res.data.decode("utf-8")
        self.assertIn("ADDITIONAL COPILOT DIAGNOSTIC AUDITS", txt)
        self.assertIn("nmap_service_detection", txt)
        self.assertIn("8080", txt)
        self.assertIn("Werkzeug/2.0.1", txt)

        # 4. CSV Export
        csv_res = self.client.get(f"/api/scan/{scan_id}/export?format=csv")
        self.assertEqual(csv_res.status_code, 200)
        csv = csv_res.data.decode("utf-8")
        self.assertIn("Copilot (nmap_service_detection)", csv)
        self.assertIn("8080", csv)

        # 5. JSON Export
        json_res = self.client.get(f"/api/scan/{scan_id}/export?format=json")
        self.assertEqual(json_res.status_code, 200)
        json_data = json_res.get_json()
        self.assertIn("copilot_command_executions", json_data)
        self.assertEqual(len(json_data["copilot_command_executions"]), 1)
        exec_record = json_data["copilot_command_executions"][0]
        self.assertEqual(exec_record["operation_id"], "nmap_service_detection")
        self.assertEqual(len(exec_record["parsed_findings"]["findings"]), 2)

        # 6. PDF Export
        pdf_res = self.client.get(f"/api/scan/{scan_id}/export?format=pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertTrue(pdf_res.data.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_res.data), 1000)

    def test_copilot_task1_ui_markup_and_routes(self):
        """
        Verify Task 1 requirements:
        - Copilot sidebar card is present in HTML returned by GET /
        - Pinned outside the scrollable nav container with mt-auto and shrink-0
        - Quick inquiry form and full Copilot view markup exist
        - Required Copilot API endpoints are reachable and return valid formats
        """
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")

        # Sidebar container and pinned button
        self.assertIn('id="sidebar-copilot-container"', html)
        self.assertIn('id="nav-link-copilot"', html)
        self.assertIn('id="sidebar-copilot-quick-form"', html)
        self.assertIn('id="sidebar-copilot-quick-input"', html)

        # Full Copilot View and Chat elements
        self.assertIn('id="view-copilot"', html)
        self.assertIn('id="copilot-chat-container"', html)
        self.assertIn('id="copilot-input-form"', html)
        self.assertIn('id="copilot-input-text"', html)
        self.assertIn('id="copilot-confirm-modal"', html)

        # Copilot operations endpoint
        ops_res = self.client.get("/api/copilot/operations")
        self.assertEqual(ops_res.status_code, 200)
        ops_data = ops_res.get_json()
        self.assertEqual(ops_data["status"], "success")
        self.assertGreaterEqual(ops_data["count"], 7)

        # Copilot conversations endpoint
        conv_res = self.client.get("/api/copilot/conversations")
        self.assertEqual(conv_res.status_code, 200)
        conv_data = conv_res.get_json()
        self.assertIsInstance(conv_data, list)

    @patch("command_runner.run_command_in_background")
    @patch("app.scan_target")
    def test_copilot_task2_natural_language_understanding_no_scan(self, mock_scan, mock_cmd_run):
        """
        Verify Task 2 requirements:
        Exact message: 'Explain what Aegis Port Scanner does. Do not run a scan.'
        - Explains Aegis is a Flask-based network security assessment dashboard using Nmap.
        - Explains the deterministic risk analyzer, scoring, storage, and reporting.
        - Responds in understandable plain English without inventing scan findings.
        - Strictly does NOT execute a scan, call scan endpoints, or trigger commands.
        - Gracefully handles AI provider availability without pretending to be live.
        """
        # 1. Send the exact message
        res = self.client.post("/api/copilot/chat", json={
            "message": "Explain what Aegis Port Scanner does. Do not run a scan."
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")

        # Verify no command card or scan command suggested
        self.assertIsNone(data.get("suggested_command"))
        self.assertIsNone(data.get("command_card"))

        # Verify plain English explanation covering confirmed project features
        reply = data.get("reply", "")
        self.assertIn("Flask", reply)
        self.assertIn("Nmap", reply)
        self.assertIn("Risk Analyzer", reply)
        self.assertIn("SQLite", reply)
        self.assertIn("Security Score", reply)
        self.assertIn("no scan was executed", reply.lower())

        # Verify scanner and command runner were NEVER called
        mock_scan.assert_not_called()
        mock_cmd_run.assert_not_called()

        # 2. Verify with mocked AI provider failure (e.g. rate limit / network error)
        with patch("ai.copilot.call_chat_messages", side_effect=Exception("Simulated provider outage")):
            res_fail = self.client.post("/api/copilot/chat", json={
                "message": "Explain what Aegis Port Scanner does. Do not run a scan."
            })
            self.assertEqual(res_fail.status_code, 200)
            data_fail = res_fail.get_json()
            self.assertEqual(data_fail["status"], "success")
            self.assertIsNone(data_fail.get("suggested_command"))
            self.assertEqual(data_fail.get("model"), "offline-expert-heuristic")
            self.assertIn("Flask", data_fail.get("reply", ""))
            mock_scan.assert_not_called()
            mock_cmd_run.assert_not_called()

        # 3. Verify with mocked successful live AI provider
        mock_ai_response = {
            "reply": "Aegis Port Scanner is a Flask-based network security assessment dashboard utilizing Nmap to scan authorized targets. Results are evaluated by a deterministic risk analyzer and stored in SQLite.",
            "suggested_command": None
        }
        with patch("ai.copilot.call_chat_messages", return_value=(mock_ai_response, "gpt-4o-mini")):
            res_live = self.client.post("/api/copilot/chat", json={
                "message": "Explain what Aegis Port Scanner does. Do not run a scan."
            })
            self.assertEqual(res_live.status_code, 200)
            data_live = res_live.get_json()
            self.assertEqual(data_live["status"], "success")
            self.assertEqual(data_live.get("model"), "gpt-4o-mini")
            self.assertIsNone(data_live.get("suggested_command"))
            self.assertIn("Flask", data_live.get("reply", ""))
            mock_scan.assert_not_called()
            mock_cmd_run.assert_not_called()

    @patch("command_runner.run_command_in_background")
    @patch("app.scan_target")
    def test_copilot_firewall_remediation_handling_and_target_binding(self, mock_scan, mock_cmd_run):
        """
        Verify reproduction and fix of user-reported manual test behavior:
        1. Turn 1 starts conversation referencing 127.0.0.1.
        2. Unrelated scan runs on 57.144.40.34.
        3. Turn 2 asks: 'run this command -> sudo ufw allow 80/tcp'.
        4. Verifies:
           - Target remains 127.0.0.1 and does NOT switch to 57.144.40.34.
           - Does NOT return a generic greeting ("Hello! I am your Aegis AI Security Copilot...").
           - Explains the UFW rule, explains Aegis does not execute privileged sudo/firewall commands.
           - Safely rejects execution: suggested_command is None.
           - scanner and command runner are never called.
        """
        # 1. Turn 1 on 127.0.0.1
        res1 = self.client.post("/api/copilot/chat", json={
            "message": "mujhe firewall bt pass karni hai ish ip addresh ki",
            "target": "127.0.0.1"
        })
        self.assertEqual(res1.status_code, 200)
        d1 = res1.get_json()
        conv_id = d1["conversation_id"]
        self.assertEqual(d1["target"], "127.0.0.1")

        # 2. Simulate an unrelated scan on 57.144.40.34 saved in DB
        scan_id_57 = database.save_scan_results("57.144.40.34", "MEDIUM", 1, [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "risk": "MEDIUM"}
        ], "quick")

        # 3. Turn 2: User sends firewall command in same conversation, with hijacked payload
        res2 = self.client.post("/api/copilot/chat", json={
            "message": "run this command -> sudo ufw allow 80/tcp",
            "conversation_id": conv_id,
            "target": "57.144.40.34",
            "scan_id": scan_id_57
        })
        self.assertEqual(res2.status_code, 200)
        d2 = res2.get_json()

        # Target MUST remain 127.0.0.1 (not hijacked to 57.144.40.34)
        self.assertEqual(d2["target"], "127.0.0.1")
        self.assertEqual(d2["conversation_id"], conv_id)

        # Execution MUST be safely rejected
        self.assertIsNone(d2.get("suggested_command"))
        self.assertIsNone(d2.get("command_card"))

        # Must NOT be a generic greeting
        reply2 = d2.get("reply", "")
        self.assertNotIn("Hello! I am your Aegis AI Security Copilot", reply2)
        self.assertIn("ufw", reply2.lower())
        self.assertIn("firewall", reply2.lower())
        self.assertIn("127.0.0.1", reply2)
        self.assertNotIn("57.144.40.34", reply2)

        # No scans or commands executed
        mock_scan.assert_not_called()
        mock_cmd_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()


