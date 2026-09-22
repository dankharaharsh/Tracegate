import os
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime

# Import application and modules
from backend.app import app
from backend import database as db
from backend import email_service
from backend import config

client = TestClient(app)


class TestEmailDeliveryUnitAndIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()

    def setUp(self):
        email_service.clear_outbox()
        self.email_test = f"user_delivery_{int(datetime.now().timestamp() * 1000)}@tracegate.test"
        self.password_orig = "ValidPassword123!"

        # Register a test user
        reg_res = client.post("/api/auth/register", json={
            "email": self.email_test,
            "username": f"user_del_{int(datetime.now().timestamp() * 1000)}",
            "password": self.password_orig,
            "full_name": "Delivery Test User"
        })
        self.assertEqual(reg_res.status_code, 201)

    def test_01_email_template_generation(self):
        """Verify HTML and plain-text email templates include the 6-digit OTP correctly."""
        otp = "741258"
        plain, html = email_service._build_email_content(otp)
        self.assertIn("741258", plain)
        self.assertIn("741258", html)
        self.assertIn("10 minutes", plain)
        self.assertIn("10 minutes", html)
        self.assertIn("TRACE", html)
        self.assertIn("GATE", html)
        self.assertIn("Tracegate Verification Code", html)
        self.assertIn("Security Notice", html)

    def test_02_is_email_configured_checks(self):
        """Test configuration detection under various environment states."""
        # 1. In testing mode
        with patch.dict(os.environ, {"TESTING": "1"}):
            self.assertTrue(email_service.is_email_configured())

        # 2. In normal mode with no config
        with patch.dict(os.environ, {"TESTING": "0"}, clear=False), \
             patch.object(email_service, "EMAIL_DEV_MODE", False), \
             patch.object(email_service, "SMTP_HOST", ""), \
             patch.object(email_service, "RESEND_API_KEY", ""):
            self.assertFalse(email_service.is_email_configured())

        # 3. With SMTP host set
        with patch.dict(os.environ, {"TESTING": "0"}, clear=False), \
             patch.object(email_service, "EMAIL_DEV_MODE", False), \
             patch.object(email_service, "SMTP_HOST", "smtp.gmail.com"), \
             patch.object(email_service, "RESEND_API_KEY", ""):
            self.assertTrue(email_service.is_email_configured())

        # 4. With Resend API key set
        with patch.dict(os.environ, {"TESTING": "0"}, clear=False), \
             patch.object(email_service, "EMAIL_DEV_MODE", False), \
             patch.object(email_service, "SMTP_HOST", ""), \
             patch.object(email_service, "RESEND_API_KEY", "re_test_key_12345"):
            self.assertTrue(email_service.is_email_configured())

    def test_03_unconfigured_email_returns_503_and_no_fake_success(self):
        """When email is not configured, requesting OTP must return HTTP 503 and never claim code was sent."""
        with patch.object(email_service, "is_email_configured", return_value=False):
            res = client.post("/api/auth/forgot-password", json={"email": self.email_test})
            self.assertEqual(res.status_code, 503)
            data = res.json()
            self.assertIn("not configured", data["detail"].lower())
            self.assertNotIn("verification code has been sent", str(data).lower())

    def test_04_smtp_delivery_failure_returns_500_and_invalidates_otp(self):
        """When SMTP delivery fails, API must return HTTP 500 and invalidate the generated OTP in database."""
        with patch.object(email_service, "is_email_configured", return_value=True), \
             patch.object(email_service, "send_password_reset_email", return_value=False):
            res = client.post("/api/auth/forgot-password", json={"email": self.email_test})
            self.assertEqual(res.status_code, 500)
            data = res.json()
            self.assertIn("unable to deliver", data["detail"].lower())

            # Verify the OTP record in the database was invalidated
            conn = db.get_db_connection()
            try:
                row = conn.execute(
                    "SELECT consumed_at FROM password_resets WHERE user_id = (SELECT id FROM users WHERE LOWER(email) = ?) ORDER BY id DESC LIMIT 1",
                    (self.email_test.lower(),)
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertIsNotNone(row["consumed_at"], "Failed delivery must invalidate the OTP record.")
            finally:
                conn.close()

    def test_05_successful_smtp_send_records_in_db_and_can_verify(self):
        """Simulate successful SMTP delivery and verify full lifecycle works end to end."""
        captured_otp = None

        def fake_send(to_email, otp):
            nonlocal captured_otp
            captured_otp = otp
            return True

        with patch.object(email_service, "is_email_configured", return_value=True), \
             patch.object(email_service, "send_password_reset_email", side_effect=fake_send):
            # 1. Send OTP
            res = client.post("/api/auth/forgot-password", json={"email": self.email_test})
            self.assertEqual(res.status_code, 200)
            self.assertIsNotNone(captured_otp)
            self.assertEqual(len(captured_otp), 6)

            # 2. Verify OTP
            v_res = client.post("/api/auth/verify-reset-otp", json={
                "email": self.email_test,
                "otp": captured_otp
            })
            self.assertEqual(v_res.status_code, 200)
            reset_auth = v_res.json().get("reset_authorization")
            self.assertTrue(reset_auth.startswith("rst-auth-"))

            # 3. Complete Reset
            new_pass = "BrandNewDeliveryPassword99!"
            rst_res = client.post("/api/auth/reset-password", json={
                "reset_authorization": reset_auth,
                "new_password": new_pass,
                "confirm_password": new_pass
            })
            self.assertEqual(rst_res.status_code, 200)

            # 4. Login with new password
            login_res = client.post("/api/auth/login", json={
                "username_or_email": self.email_test,
                "password": new_pass
            })
            self.assertEqual(login_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
