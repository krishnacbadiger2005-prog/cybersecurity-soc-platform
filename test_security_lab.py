"""
test_security_lab.py — Test Suite for Phase 3 Security Lab Dashboard
====================================================================
Tests the database query layer, Flask application routes, JSON API,
and end-to-end integration with the shared security.db database.
"""

import sys
import os
import unittest
import json
import importlib.util

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.join(PROJECT_ROOT, "security-lab")

# Preserve original database module if already loaded
_original_database_module = sys.modules.get("database")

# Import root portfolio database module
portfolio_db_spec = importlib.util.spec_from_file_location("portfolio_database", os.path.join(PROJECT_ROOT, "database.py"))
portfolio_db = importlib.util.module_from_spec(portfolio_db_spec)
portfolio_db_spec.loader.exec_module(portfolio_db)

# Import security-lab database module
lab_db_spec = importlib.util.spec_from_file_location("lab_database", os.path.join(LAB_DIR, "database.py"))
lab_db = importlib.util.module_from_spec(lab_db_spec)
lab_db_spec.loader.exec_module(lab_db)

# Temporarily register lab_db as 'database' for app import
sys.modules["database"] = lab_db
lab_app_spec = importlib.util.spec_from_file_location("lab_app", os.path.join(LAB_DIR, "app.py"))
lab_app_module = importlib.util.module_from_spec(lab_app_spec)
lab_app_spec.loader.exec_module(lab_app_module)
lab_app = lab_app_module.app


# Import security-lab reports module
lab_reports_spec = importlib.util.spec_from_file_location("lab_reports", os.path.join(LAB_DIR, "reports.py"))
lab_reports = importlib.util.module_from_spec(lab_reports_spec)
lab_reports_spec.loader.exec_module(lab_reports)

# Immediately restore portfolio database module in sys.modules so other test suites are unaffected
if _original_database_module is not None:
    sys.modules["database"] = _original_database_module
else:
    sys.modules["database"] = portfolio_db


def tearDownModule():
    """Ensure root portfolio database module is restored after this test module runs."""
    sys.modules["database"] = portfolio_db


class TestSecurityLabDatabase(unittest.TestCase):
    """Test all database query functions in security-lab/database.py."""

    def test_database_connection(self):
        conn = lab_db.get_db()
        self.assertIsNotNone(conn)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_total_attempts(self):
        total = lab_db.get_total_attempts()
        self.assertIsInstance(total, int)
        self.assertGreaterEqual(total, 0)

    def test_successful_attempts(self):
        success = lab_db.get_successful_attempts()
        self.assertIsInstance(success, int)
        self.assertGreaterEqual(success, 0)

    def test_failed_attempts(self):
        failed = lab_db.get_failed_attempts()
        self.assertIsInstance(failed, int)
        self.assertGreaterEqual(failed, 0)

    def test_recent_events(self):
        events = lab_db.get_recent_events(limit=5)
        self.assertIsInstance(events, list)
        for ev in events:
            self.assertIn("id", ev)
            self.assertIn("username", ev)
            self.assertIn("ip_address", ev)
            self.assertIn("timestamp", ev)
            self.assertIn("status", ev)

    def test_top_source_ips(self):
        top_ips = lab_db.get_top_source_ips(limit=5)
        self.assertIsInstance(top_ips, list)
        for item in top_ips:
            self.assertIn("ip_address", item)
            self.assertIn("count", item)

    def test_get_dashboard_data_structure(self):
        data = lab_db.get_dashboard_data()
        required_keys = [
            "total_attempts",
            "successful_attempts",
            "failed_attempts",
            "success_rate",
            "failure_rate",
            "recent_events",
            "top_source_ips",
        ]
        for key in required_keys:
            self.assertIn(key, data)
        self.assertEqual(data["total_attempts"], data["successful_attempts"] + data["failed_attempts"])


class TestSecurityLabApp(unittest.TestCase):
    """Test Security Lab Flask routes and responses."""

    def setUp(self):
        lab_app.config["TESTING"] = True
        self.client = lab_app.test_client()

    def test_dashboard_route_home(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        # Verify core Phase 3 dashboard components are rendered
        self.assertIn(b"Total Authentication Attempts", resp.data)
        self.assertIn(b"Successful Attempts", resp.data)
        self.assertIn(b"Failed Attempts", resp.data)
        self.assertIn(b"Top Source IPs", resp.data)
        self.assertIn(b"Recent Events", resp.data)

    def test_dashboard_route_alias(self):
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SOC Authentication Telemetry", resp.data)

    def test_api_metrics_endpoint(self):
        resp = self.client.get("/api/metrics")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "application/json")
        data = json.loads(resp.data.decode("utf-8"))
        self.assertIn("total_attempts", data)
        self.assertIn("successful_attempts", data)
        self.assertIn("failed_attempts", data)
        self.assertIn("recent_events", data)
        self.assertIn("top_source_ips", data)


class TestPortfolioSecurityLabIntegration(unittest.TestCase):
    """Verify that portfolio writes are immediately visible to security-lab."""

    TEST_USER = "sec_lab_integration_user"
    TEST_IP = "198.51.100.77"

    def tearDown(self):
        conn = lab_db.get_db()
        conn.execute("DELETE FROM login_events WHERE username = ?", (self.TEST_USER,))
        conn.commit()
        conn.close()

    def test_live_telemetry_flow(self):
        initial_data = lab_db.get_dashboard_data()
        initial_total = initial_data["total_attempts"]
        initial_failed = initial_data["failed_attempts"]

        # Portfolio writes a failed login event
        portfolio_db.log_login_event(self.TEST_USER, self.TEST_IP, "FAILED")

        # Security Lab immediately reads the updated counts
        updated_data = lab_db.get_dashboard_data()
        self.assertEqual(updated_data["total_attempts"], initial_total + 1)
        self.assertEqual(updated_data["failed_attempts"], initial_failed + 1)

        # Verify event appears in recent events
        recent_usernames = [e["username"] for e in updated_data["recent_events"]]
        self.assertIn(self.TEST_USER, recent_usernames)

        # Verify IP appears in top source IPs
        ips = [i["ip_address"] for i in updated_data["top_source_ips"]]
        self.assertIn(self.TEST_IP, ips)


class TestRepeatedFailureDetector(unittest.TestCase):
    """Test repeated failure / brute force detection in security-lab/detector.py."""

    BRUTE_IP = "192.0.2.222"
    BRUTE_USER = "brute_target"

    def tearDown(self):
        conn = lab_db.get_connection()
        conn.execute("DELETE FROM login_events WHERE ip_address = ?", (self.BRUTE_IP,))
        conn.commit()
        conn.close()

    def test_detector_threshold(self):
        detector_spec = importlib.util.spec_from_file_location("detector", os.path.join(LAB_DIR, "detector.py"))
        detector = importlib.util.module_from_spec(detector_spec)
        detector_spec.loader.exec_module(detector)
        # Initially no suspicious IPs for BRUTE_IP
        suspicious = [ip for ip, _ in detector.detect_suspicious_ips()]
        self.assertNotIn(self.BRUTE_IP, suspicious)

        # Log 5 failed attempts from BRUTE_IP
        for _ in range(5):
            portfolio_db.log_login_event(self.BRUTE_USER, self.BRUTE_IP, "FAILED")

        # Now detector MUST flag BRUTE_IP
        detected = detector.detect_suspicious_ips()
        detected_dict = dict(detected)
        self.assertIn(self.BRUTE_IP, detected_dict)
        self.assertGreaterEqual(detected_dict[self.BRUTE_IP], 5)

    def test_dashboard_renders_detector_section(self):
        client = lab_app.test_client()
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Detected Repeated Failures", resp.data)


class TestPhase5SecurityDashboard(unittest.TestCase):
    """Test Phase 5 Security Dashboard features: 4 containers, alerts, timeline, filtering."""

    def setUp(self):
        lab_app.config["TESTING"] = True
        self.client = lab_app.test_client()

    def test_dashboard_stats_keys(self):
        stats = lab_db.get_dashboard_stats()
        self.assertIn("successful_logins", stats)
        self.assertIn("failed_logins", stats)
        self.assertIn("suspicious_activity", stats)
        self.assertIn("security_alerts", stats)
        self.assertIsInstance(stats["successful_logins"], int)
        self.assertIsInstance(stats["failed_logins"], int)

    def test_security_alerts_query(self):
        alerts = lab_db.get_security_alerts(limit=5)
        self.assertIsInstance(alerts, list)

    def test_login_timeline_query(self):
        timeline = lab_db.get_login_timeline()
        self.assertIsInstance(timeline, list)

    def test_dashboard_four_containers_rendered(self):
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Successful Logins", resp.data)
        self.assertIn(b"Failed Logins", resp.data)
        self.assertIn(b"Suspicious Activity", resp.data)
        self.assertIn(b"Security Alerts", resp.data)

    def test_dashboard_charts_and_tables_rendered(self):
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Login Attempts Over Time", resp.data)
        self.assertIn(b"Failed vs Successful", resp.data)
        self.assertIn(b"Top Source IPs", resp.data)
        self.assertIn(b"timelineChart", resp.data)
        self.assertIn(b"ratioChart", resp.data)
        self.assertIn(b"topIpsChart", resp.data)

    def test_time_range_filter(self):
        for r in ("15m", "1h", "24h", "7d", "all"):
            resp = self.client.get(f"/dashboard?range={r}")
            self.assertEqual(resp.status_code, 200)


class TestPhase6SecurityReporting(unittest.TestCase):
    """Test Phase 6 Security Reporting: CSV & PDF generation, date filtering, and download routes."""

    def setUp(self):
        lab_app.config["TESTING"] = True
        self.client = lab_app.test_client()

    def test_generate_security_report_csv_structure(self):
        events = [
            {"id": 1, "username": "krishna", "ip_address": "127.0.0.1", "status": "SUCCESS", "timestamp": "2026-09-20 10:00:00"},
            {"id": 2, "username": "attacker", "ip_address": "10.0.0.1", "status": "FAILED", "timestamp": "2026-09-20 10:01:00"},
            {"id": 3, "username": "attacker", "ip_address": "10.0.0.1", "status": "FAILED", "timestamp": "2026-09-20 10:02:00"}
        ]
        alerts = [
            {"id": 1, "ip_address": "10.0.0.1", "attempt_count": 5, "severity": "HIGH", "description": "Brute force attempt", "timestamp": "2026-09-20 10:02:00"}
        ]
        csv_text = lab_reports.generate_security_report(events, alerts, "2026-09-01", "2026-09-20")

        # Step 6, 7, 8, 9, 10, 11: Summary checks
        self.assertIn("Security Monitoring Report", csv_text)
        self.assertIn("Period,2026-09-01 to 2026-09-20", csv_text)
        self.assertIn("Total Attempts,3", csv_text)
        self.assertIn("Successful,1", csv_text)
        self.assertIn("Failed,2", csv_text)
        self.assertIn("Suspicious IPs,1", csv_text)
        self.assertIn("Alerts Generated,1", csv_text)

        # Step 12, 13, 14: Authentication Events checks
        self.assertIn("Authentication Events", csv_text)
        self.assertIn("ID,Username,IP Address,Status,Timestamp", csv_text)
        self.assertIn("1,krishna,127.0.0.1,SUCCESS,2026-09-20 10:00:00", csv_text)
        self.assertIn("2,attacker,10.0.0.1,FAILED,2026-09-20 10:01:00", csv_text)

        # Step 15: Security Alerts checks
        self.assertIn("Security Alerts", csv_text)
        self.assertIn("ID,IP Address,Attempts,Severity,Description,Timestamp", csv_text)
        self.assertIn("1,10.0.0.1,5,HIGH,Brute force attempt,2026-09-20 10:02:00", csv_text)

    def test_generate_security_pdf_structure(self):
        events = [
            {"id": 1, "username": "krishna", "ip_address": "127.0.0.1", "status": "SUCCESS", "timestamp": "2026-09-20 10:00:00"},
            {"id": 2, "username": "attacker", "ip_address": "10.0.0.1", "status": "FAILED", "timestamp": "2026-09-20 10:01:00"}
        ]
        alerts = [
            {"id": 1, "ip_address": "10.0.0.1", "attempt_count": 5, "severity": "HIGH", "description": "Brute force attempt", "timestamp": "2026-09-20 10:02:00"}
        ]
        pdf_bytes = lab_reports.generate_security_pdf(events, alerts, "2026-09-01", "2026-09-20")
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 1000)

    def test_export_report_csv_route(self):
        resp = self.client.get("/export-report")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        disposition = resp.headers.get("Content-Disposition", "")
        self.assertIn("attachment", disposition)
        self.assertIn("security_report_", disposition)
        self.assertIn(".csv", disposition)
        self.assertIn(b"Security Monitoring Report", resp.data)
        self.assertIn(b"Authentication Events", resp.data)

    def test_export_report_date_filtering(self):
        resp = self.client.get("/export-report?start_date=2026-09-01&end_date=2026-09-20")
        self.assertEqual(resp.status_code, 200)
        disposition = resp.headers.get("Content-Disposition", "")
        self.assertIn("security_report_2026-09-01_to_2026-09-20.csv", disposition)
        self.assertIn(b"2026-09-01 to 2026-09-20", resp.data)

    def test_export_report_invalid_date_range(self):
        resp = self.client.get("/export-report?start_date=2026-09-30&end_date=2026-09-01")
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid date range", resp.data)

    def test_export_report_pdf_route(self):
        resp = self.client.get("/export-report?format=pdf")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/pdf", resp.content_type)
        disposition = resp.headers.get("Content-Disposition", "")
        self.assertIn(".pdf", disposition)
        self.assertTrue(resp.data.startswith(b"%PDF"))

    def test_export_pdf_direct_route(self):
        resp = self.client.get("/export-pdf")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/pdf", resp.content_type)
        self.assertTrue(resp.data.startswith(b"%PDF"))

    def test_dashboard_renders_export_controls(self):
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"export-panel", resp.data)
        self.assertIn(b"Export Security Report", resp.data)
        self.assertIn(b"Export CSV", resp.data)
        self.assertIn(b"Export PDF", resp.data)
        self.assertIn(b"action=\"/export-report\"", resp.data)
        self.assertIn(b"name=\"start_date\"", resp.data)
        self.assertIn(b"name=\"end_date\"", resp.data)


if __name__ == "__main__":
    unittest.main()


