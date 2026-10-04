"""
test_phase7_linux_parser.py — Comprehensive Test Suite for Phase 7
===================================================================
Validates Linux authentication log parsing, SQLite telemetry ingestion,
event source segregation (PORTFOLIO vs LINUX), deduplication hashing,
brute-force detection engine integration, and SOC dashboard source filtering.
"""

import os
import sys
import unittest
import sqlite3
import importlib.util
import json

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.join(PROJECT_ROOT, "security-lab")
SAMPLE_LOG = os.path.join(LAB_DIR, "sample_logs", "auth.log")

# Load parser module
parser_spec = importlib.util.spec_from_file_location("log_parser", os.path.join(LAB_DIR, "log_parser.py"))
log_parser = importlib.util.module_from_spec(parser_spec)
parser_spec.loader.exec_module(log_parser)

# Load lab database module
lab_db_spec = importlib.util.spec_from_file_location("lab_database", os.path.join(LAB_DIR, "database.py"))
lab_db = importlib.util.module_from_spec(lab_db_spec)
lab_db_spec.loader.exec_module(lab_db)

# Load detector module
detector_spec = importlib.util.spec_from_file_location("lab_detector", os.path.join(LAB_DIR, "detector.py"))
lab_detector = importlib.util.module_from_spec(detector_spec)
detector_spec.loader.exec_module(lab_detector)

# Load lab app module
lab_app_spec = importlib.util.spec_from_file_location("lab_app", os.path.join(LAB_DIR, "app.py"))
lab_app_module = importlib.util.module_from_spec(lab_app_spec)
lab_app_spec.loader.exec_module(lab_app_module)
lab_app = lab_app_module.app

# Load root portfolio db
portfolio_db_spec = importlib.util.spec_from_file_location("portfolio_db", os.path.join(PROJECT_ROOT, "database.py"))
portfolio_db = importlib.util.module_from_spec(portfolio_db_spec)
portfolio_db_spec.loader.exec_module(portfolio_db)


def setUpModule():
    """Ensure sample logs and database events are present before running tests."""
    sample_text = """Sep 20 10:01:15 ubuntu sshd[1001]: Accepted password for krishna from 192.168.1.10 port 52341 ssh2
Sep 20 10:02:10 ubuntu sshd[1002]: Failed password for krishna from 192.168.1.20 port 52342 ssh2
Sep 20 10:02:15 ubuntu sshd[1003]: Failed password for krishna from 192.168.1.20 port 52343 ssh2
Sep 20 10:02:20 ubuntu sshd[1004]: Failed password for krishna from 192.168.1.20 port 52344 ssh2
Sep 20 10:02:25 ubuntu sshd[1005]: Failed password for krishna from 192.168.1.20 port 52345 ssh2
Sep 20 10:02:30 ubuntu sshd[1006]: Failed password for krishna from 192.168.1.20 port 52346 ssh2
Sep 20 10:03:10 ubuntu sshd[1007]: Accepted password for krishna from 192.168.1.10 port 52347 ssh2
Sep 20 10:04:10 ubuntu sshd[1008]: Failed password for test from 10.0.0.5 port 52348 ssh2
Sep 20 10:04:20 ubuntu sshd[1009]: Failed password for test from 10.0.0.5 port 52349 ssh2
"""
    for p in (SAMPLE_LOG, os.path.join(PROJECT_ROOT, "sample_logs", "auth.log")):
        with open(p, "w", encoding="utf-8") as f:
            f.write(sample_text)
    events = log_parser.parse_log_file(SAMPLE_LOG)
    log_parser.insert_events(events, source="LINUX_AUTH_LOG")


class TestLinuxLogParser(unittest.TestCase):
    """Test log_parser.py parsing logic and field extractions (Steps 3-13)."""

    def test_sample_auth_log_file_exists(self):
        """Verify sample_logs/auth.log exists and is non-empty (Step 1 & 2)."""
        self.assertTrue(os.path.exists(SAMPLE_LOG), f"Missing {SAMPLE_LOG}")
        with open(SAMPLE_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 9, "auth.log must contain exactly 9 sample lines")

    def test_parse_successful_log_line(self):
        """Verify parsing of Accepted password event (Steps 6, 8, 9, 10, 11)."""
        line = "Sep 20 10:01:15 ubuntu sshd[1001]: Accepted password for krishna from 192.168.1.10 port 52341 ssh2"
        event = log_parser.parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "krishna")
        self.assertEqual(event["ip_address"], "192.168.1.10")
        self.assertEqual(event["status"], "SUCCESS")
        self.assertEqual(event["timestamp"], "Sep 20 10:01:15")

    def test_parse_failed_log_line(self):
        """Verify parsing of Failed password event (Steps 6, 7, 9, 10, 11)."""
        line = "Sep 20 10:02:10 ubuntu sshd[1002]: Failed password for krishna from 192.168.1.20 port 52342 ssh2"
        event = log_parser.parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "krishna")
        self.assertEqual(event["ip_address"], "192.168.1.20")
        self.assertEqual(event["status"], "FAILED")
        self.assertEqual(event["timestamp"], "Sep 20 10:02:10")

    def test_parse_invalid_user_failed_line(self):
        """Verify parsing of Failed password for invalid user."""
        line = "Sep 20 10:05:00 ubuntu sshd[1010]: Failed password for invalid user admin from 10.10.10.10 port 44321 ssh2"
        event = log_parser.parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["ip_address"], "10.10.10.10")
        self.assertEqual(event["status"], "FAILED")

    def test_ignore_unrelated_log_line(self):
        """Verify parser safely ignores non-authentication syslog lines."""
        line = "Sep 20 10:00:01 ubuntu CRON[999]: (root) CMD (/usr/lib/sysstat/sa1 1 1)"
        event = log_parser.parse_log_line(line)
        self.assertIsNone(event)

    def test_parse_log_file_entirety(self):
        """Verify parse_log_file accurately reads and parses sample_logs/auth.log (Step 12)."""
        events = log_parser.parse_log_file(SAMPLE_LOG)
        self.assertEqual(len(events), 9)

        success_count = sum(1 for e in events if e["status"] == "SUCCESS")
        failed_count = sum(1 for e in events if e["status"] == "FAILED")
        self.assertEqual(success_count, 2, "Expected 2 successful logins in auth.log")
        self.assertEqual(failed_count, 7, "Expected 7 failed logins in auth.log")

        # Verify suspicious IP 192.168.1.20 has 5 failed attempts
        ip_20_failures = [e for e in events if e["ip_address"] == "192.168.1.20" and e["status"] == "FAILED"]
        self.assertEqual(len(ip_20_failures), 5)


class TestDatabaseIngestionAndDeduplication(unittest.TestCase):
    """Test SQLite ingestion, source tagging, and deduplication (Steps 14-19, 26)."""

    TEST_DB = os.path.join(LAB_DIR, "test_phase7_temp.db")

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        conn = sqlite3.connect(self.TEST_DB)
        log_parser.ensure_db_schema(conn)
        conn.close()

    def tearDown(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)

    def test_deduplication_hashing(self):
        """Verify compute_event_hash produces deterministic SHA-256 (Step 26)."""
        ev = {"username": "krishna", "ip_address": "192.168.1.20", "status": "FAILED", "timestamp": "Sep 20 10:02:10"}
        h1 = log_parser.compute_event_hash(ev, source="LINUX_AUTH_LOG")
        h2 = log_parser.compute_event_hash(ev, source="LINUX_AUTH_LOG")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

        # Different IP should yield different hash
        ev_diff = {"username": "krishna", "ip_address": "192.168.1.21", "status": "FAILED", "timestamp": "Sep 20 10:02:10"}
        h_diff = log_parser.compute_event_hash(ev_diff, source="LINUX_AUTH_LOG")
        self.assertNotEqual(h1, h_diff)

    def test_insert_and_prevent_duplicates(self):
        """Verify running parser multiple times prevents duplicate records (Step 26)."""
        events = log_parser.parse_log_file(SAMPLE_LOG)

        # 1st Run: Inserts all 9 events
        res1 = log_parser.insert_events(events, db_path=self.TEST_DB, source="LINUX_AUTH_LOG")
        self.assertEqual(res1["parsed"], 9)
        self.assertEqual(res1["inserted"], 9)
        self.assertEqual(res1["duplicates"], 0)

        # Verify in DB
        conn = sqlite3.connect(self.TEST_DB)
        count = conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
        self.assertEqual(count, 9)

        # Verify source column is LINUX_AUTH_LOG (Step 16)
        sources = [r[0] for r in conn.execute("SELECT DISTINCT source FROM login_events").fetchall()]
        self.assertEqual(sources, ["LINUX_AUTH_LOG"])
        conn.close()

        # 2nd Run: Should insert 0 events and skip 9 duplicates
        res2 = log_parser.insert_events(events, db_path=self.TEST_DB, source="LINUX_AUTH_LOG")
        self.assertEqual(res2["parsed"], 9)
        self.assertEqual(res2["inserted"], 0)
        self.assertEqual(res2["duplicates"], 9)

        # Verify count is still exactly 9
        conn = sqlite3.connect(self.TEST_DB)
        count_after = conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
        self.assertEqual(count_after, 9)
        conn.close()


class TestBruteForceDetectionIntegration(unittest.TestCase):
    """Test detection engine analyzing Linux auth events (Step 20)."""

    def test_detector_identifies_suspicious_linux_ip(self):
        """Verify 192.168.1.20 (5 failures) is flagged and 10.0.0.5 (2 failures) is not."""
        suspicious_list = lab_detector.detect_suspicious_ips()
        suspicious_ips = [ip for ip, _ in suspicious_list]
        self.assertIn("192.168.1.20", suspicious_ips, "192.168.1.20 must be flagged as SUSPICIOUS")
        self.assertNotIn("10.0.0.5", suspicious_ips, "10.0.0.5 (2 failures) must NOT be flagged")

        # Verify failure count is at least 5
        detected_dict = dict(suspicious_list)
        self.assertGreaterEqual(detected_dict["192.168.1.20"], 5)


class TestDashboardSourceFilteringAndUI(unittest.TestCase):
    """Test dashboard UI rendering source column and source filter (Steps 21, 22, 23)."""

    def setUp(self):
        lab_app.config["TESTING"] = True
        self.client = lab_app.test_client()

    def test_dashboard_renders_source_column_and_controls(self):
        """Verify dashboard HTML includes Source header, filter dropdown, and source badges."""
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)

        # Step 22: Table header includes 'Source'
        self.assertIn(b"<th>Source</th>", resp.data)

        # Step 23: Dropdown includes 'Event Source' options
        self.assertIn(b"Event Source:", resp.data)
        self.assertIn(b"All Sources", resp.data)
        self.assertIn(b"Portfolio", resp.data)
        self.assertIn(b"Linux Authentication", resp.data)

        # Badges rendered
        self.assertIn(b"badge-linux", resp.data)
        self.assertIn(b"LINUX", resp.data)

    def test_dashboard_source_filter_linux(self):
        """Verify filtering by source=linux returns only Linux events."""
        resp = self.client.get("/dashboard?source=linux")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"LINUX", resp.data)

    def test_dashboard_source_filter_portfolio(self):
        """Verify filtering by source=portfolio returns only Portfolio events."""
        resp = self.client.get("/dashboard?source=portfolio")
        self.assertEqual(resp.status_code, 200)

    def test_api_metrics_with_source_filter(self):
        """Verify /api/metrics respects source parameter."""
        resp = self.client.get("/api/metrics?source=linux")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data.decode("utf-8"))
        self.assertIn("current_source", data)
        self.assertEqual(data["current_source"], "linux")
        for ev in data["recent_events"]:
            self.assertIn("LINUX", ev.get("source", ""))


class TestPortfolioAppRegression(unittest.TestCase):
    """Ensure Portfolio authentication logging still works and tags PORTFOLIO."""

    def test_portfolio_log_login_event_tags_portfolio(self):
        test_ip = "127.0.0.99"
        portfolio_db.log_login_event("regression_test_user", test_ip, "SUCCESS")

        conn = portfolio_db.get_db()
        row = conn.execute(
            "SELECT username, ip_address, status, source FROM login_events WHERE ip_address = ?",
            (test_ip,)
        ).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "regression_test_user")
        self.assertEqual(row["status"], "SUCCESS")
        self.assertEqual(row["source"], "PORTFOLIO")

        # Cleanup
        conn = portfolio_db.get_db()
        conn.execute("DELETE FROM login_events WHERE ip_address = ?", (test_ip,))
        conn.commit()
        conn.close()


class TestClearLogsFunctionality(unittest.TestCase):
    """Test the Clear logs button and database reset functionality."""

    def setUp(self):
        lab_app.config["TESTING"] = True
        self.client = lab_app.test_client()

    def test_dashboard_renders_clear_button(self):
        """Verify the Clear button is rendered in the top-right header controls."""
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"btn-clear-logs", resp.data)
        self.assertIn(b"action=\"/clear-logs\"", resp.data)
        self.assertIn(b"Clear", resp.data)

    def test_clear_logs_route_resets_database(self):
        """Verify calling /clear-logs clears all login events and alerts."""
        # Insert a sample event
        portfolio_db.log_login_event("test_clear_user", "10.99.99.99", "FAILED")

        # Call clear-logs route
        resp = self.client.post("/clear-logs", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Verify database login_events is empty
        conn = lab_db.get_connection()
        count_events = conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
        count_alerts = conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]
        conn.close()

        self.assertEqual(count_events, 0, "All login events must be cleared")
        self.assertEqual(count_alerts, 0, "All security alerts must be cleared")

        # Verify new incoming events can immediately be added fresh
        portfolio_db.log_login_event("fresh_user", "127.0.0.1", "SUCCESS")
        conn = lab_db.get_connection()
        count_after = conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
        conn.close()
        self.assertEqual(count_after, 1, "Fresh upcoming logs should be recorded normally")

    def tearDown(self):
        sample_text = """Sep 20 10:01:15 ubuntu sshd[1001]: Accepted password for krishna from 192.168.1.10 port 52341 ssh2
Sep 20 10:02:10 ubuntu sshd[1002]: Failed password for krishna from 192.168.1.20 port 52342 ssh2
Sep 20 10:02:15 ubuntu sshd[1003]: Failed password for krishna from 192.168.1.20 port 52343 ssh2
Sep 20 10:02:20 ubuntu sshd[1004]: Failed password for krishna from 192.168.1.20 port 52344 ssh2
Sep 20 10:02:25 ubuntu sshd[1005]: Failed password for krishna from 192.168.1.20 port 52345 ssh2
Sep 20 10:02:30 ubuntu sshd[1006]: Failed password for krishna from 192.168.1.20 port 52346 ssh2
Sep 20 10:03:10 ubuntu sshd[1007]: Accepted password for krishna from 192.168.1.10 port 52347 ssh2
Sep 20 10:04:10 ubuntu sshd[1008]: Failed password for test from 10.0.0.5 port 52348 ssh2
Sep 20 10:04:20 ubuntu sshd[1009]: Failed password for test from 10.0.0.5 port 52349 ssh2
"""
        for p in (SAMPLE_LOG, os.path.join(PROJECT_ROOT, "sample_logs", "auth.log")):
            with open(p, "w", encoding="utf-8") as f:
                f.write(sample_text)
        events = log_parser.parse_log_file(SAMPLE_LOG)
        log_parser.insert_events(events, source="LINUX_AUTH_LOG")


if __name__ == "__main__":
    unittest.main()
