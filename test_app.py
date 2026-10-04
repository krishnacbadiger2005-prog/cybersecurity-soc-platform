import os
import unittest
from app import app
from database import init_db, get_db

class TestAuthPipeline(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        init_db()
        conn = get_db()
        conn.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.execute("DELETE FROM login_events WHERE username = 'testuser'")
        conn.commit()
        conn.close()

    def tearDown(self):
        conn = get_db()
        conn.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.execute("DELETE FROM login_events WHERE username = 'testuser'")
        conn.commit()
        conn.close()

    def test_pipeline(self):
        # 1. Unauthenticated access to / redirects or errors
        resp = self.client.get("/", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

        # 2. Access /portfolio unauthenticated returns error
        resp = self.client.get("/portfolio")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Authentication required", resp.data)

        # 3. Register a test user
        resp = self.client.post("/register", data={
            "username": "testuser",
            "password": "SecretPassword123!"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Portfolio Login", resp.data)

        # 4. Attempt registering the duplicate username
        resp = self.client.post("/register", data={
            "username": "testuser",
            "password": "AnotherPassword"
        })
        self.assertIn(b"Username already exists", resp.data)

        # 5. Login with invalid password fails
        resp = self.client.post("/login", data={
            "username": "testuser",
            "password": "WrongPassword"
        })
        self.assertIn(b"Authentication failed", resp.data)

        # Verify failed login event was logged
        conn = get_db()
        failed_event = conn.execute(
            "SELECT * FROM login_events WHERE username = 'testuser' AND status = 'FAILED'"
        ).fetchone()
        self.assertIsNotNone(failed_event)
        self.assertEqual(failed_event["status"], "FAILED")
        self.assertEqual(failed_event["username"], "testuser")
        self.assertTrue(failed_event["ip_address"])
        self.assertTrue(failed_event["timestamp"])
        conn.close()

        # 6. Login with valid password succeeds
        resp = self.client.post("/login", data={
            "username": "testuser",
            "password": "SecretPassword123!"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Welcome to My Portfolio", resp.data)
        self.assertIn(b"testuser", resp.data)

        # Verify successful login event was logged
        conn = get_db()
        success_event = conn.execute(
            "SELECT * FROM login_events WHERE username = 'testuser' AND status = 'SUCCESS'"
        ).fetchone()
        self.assertIsNotNone(success_event)
        self.assertEqual(success_event["status"], "SUCCESS")
        self.assertEqual(success_event["username"], "testuser")
        self.assertTrue(success_event["ip_address"])
        self.assertTrue(success_event["timestamp"])
        conn.close()

        # 7. Access /portfolio while logged in
        resp = self.client.get("/portfolio")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Welcome, testuser", resp.data)

        # 8. Logout
        resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Portfolio Login", resp.data)

        # 9. Verify /portfolio is blocked again after logout
        resp = self.client.get("/portfolio")
        self.assertIn(b"Authentication required", resp.data)

    def test_direct_log_login_event(self):
        from database import log_login_event
        log_login_event("testuser", "192.168.1.100", "SUCCESS")
        conn = get_db()
        event = conn.execute(
            "SELECT * FROM login_events WHERE username = 'testuser' AND ip_address = '192.168.1.100'"
        ).fetchone()
        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "testuser")
        self.assertEqual(event["ip_address"], "192.168.1.100")
        self.assertEqual(event["status"], "SUCCESS")
        self.assertTrue(event["timestamp"])
        conn.close()

if __name__ == "__main__":
    unittest.main()

