import unittest
import hashlib
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from pathlib import Path

# Ensure testing environment
import os
os.environ["TESTING"] = "1"
os.environ["EMAIL_DEV_MODE"] = "true"

from backend.app import app
from backend import database as db
from backend import email_service

client = TestClient(app)


class TestPasswordResetOtpComplete(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()

    def setUp(self):
        email_service.clear_outbox()
        self.email_a = f"testuser_a_{int(datetime.now().timestamp() * 1000)}@tracegate.test"
        self.email_b = f"testuser_b_{int(datetime.now().timestamp() * 1000)}@tracegate.test"
        self.password_orig = "OriginalSecretPassword123!"

        # Register User A
        reg_a = client.post("/api/auth/register", json={
            "email": self.email_a,
            "username": f"user_a_{int(datetime.now().timestamp() * 1000)}",
            "password": self.password_orig,
            "full_name": "Test User A"
        })
        self.assertEqual(reg_a.status_code, 201)

        # Register User B
        reg_b = client.post("/api/auth/register", json={
            "email": self.email_b,
            "username": f"user_b_{int(datetime.now().timestamp() * 1000)}",
            "password": self.password_orig,
            "full_name": "Test User B"
        })
        self.assertEqual(reg_b.status_code, 201)

    def _clear_cooldown(self, email: str):
        """Helper to clear rate-limiting cooldown timestamps for fast testing."""
        conn = db.get_db_connection()
        conn.execute(
            "UPDATE password_resets SET created_at = datetime('now', '-5 minutes') WHERE user_id = (SELECT id FROM users WHERE LOWER(email) = ?)",
            (email.strip().lower(),)
        )
        conn.commit()
        conn.close()

    # =========================================================================
    # TEST 1 — NORMAL FORGOT PASSWORD
    # =========================================================================
    def test_01_normal_forgot_password(self):
        """Enter valid registered email: OTP email dispatched, NOT in response, NOT in UI."""
        res = client.post("/api/auth/forgot-password", json={"email": self.email_a})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Account enumeration defense: generic response
        self.assertIn("verification code has been sent", data["message"].lower())

        # CRITICAL: Response must NEVER contain OTP or reset token
        self.assertNotIn("otp", data)
        self.assertNotIn("token", data)
        self.assertNotIn("reset_token", data)
        self.assertNotIn("secret", data)

        # Outbox verification
        otp = email_service.get_last_otp_for_email(self.email_a)
        self.assertIsNotNone(otp, "OTP must be dispatched to registered email outbox.")
        self.assertEqual(len(otp), 6, "OTP must be exactly 6 digits.")
        self.assertTrue(otp.isdigit(), "OTP must be numeric digits.")

    # =========================================================================
    # TEST 2 — VERIFY VALID OTP
    # =========================================================================
    def test_02_verify_valid_otp(self):
        """Enter correct OTP: verification succeeds, reset authorization returned, password fields unlockable."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)
        self.assertIsNotNone(otp)

        verify_res = client.post("/api/auth/verify-reset-otp", json={
            "email": self.email_a,
            "otp": otp
        })
        self.assertEqual(verify_res.status_code, 200)
        data = verify_res.json()
        self.assertIn("confirmed", data["message"].lower())
        self.assertIsNotNone(data.get("reset_authorization"))
        self.assertTrue(data["reset_authorization"].startswith("rst-auth-"))

    # =========================================================================
    # TEST 3 — WRONG OTP
    # =========================================================================
    def test_03_wrong_otp_rejected(self):
        """Enter incorrect OTP: verification rejected with 400 Bad Request."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        real_otp = email_service.get_last_otp_for_email(self.email_a)
        wrong_otp = "000000" if real_otp != "000000" else "111111"

        verify_res = client.post("/api/auth/verify-reset-otp", json={
            "email": self.email_a,
            "otp": wrong_otp
        })
        self.assertEqual(verify_res.status_code, 400)
        self.assertIn("invalid verification code", verify_res.json()["detail"].lower())

    # =========================================================================
    # TEST 4 — TOO MANY ATTEMPTS
    # =========================================================================
    def test_04_too_many_attempts_invalidates_otp(self):
        """Enter incorrect OTP repeatedly: after 5 attempts, OTP is invalidated and rejected even if correct."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        real_otp = email_service.get_last_otp_for_email(self.email_a)

        # First 4 incorrect attempts show remaining count
        for i in range(4):
            res = client.post("/api/auth/verify-reset-otp", json={
                "email": self.email_a,
                "otp": f"99999{i}"
            })
            self.assertEqual(res.status_code, 400)
            self.assertIn("remaining", res.json()["detail"].lower())

        # 5th incorrect attempt invalidates the OTP
        res_5 = client.post("/api/auth/verify-reset-otp", json={
            "email": self.email_a,
            "otp": "999994"
        })
        self.assertEqual(res_5.status_code, 400)
        self.assertIn("invalidated", res_5.json()["detail"].lower())

        # Subsequent attempt with the CORRECT OTP must now fail because OTP was invalidated
        correct_res = client.post("/api/auth/verify-reset-otp", json={
            "email": self.email_a,
            "otp": real_otp
        })
        self.assertEqual(correct_res.status_code, 400)

    # =========================================================================
    # TEST 5 — EXPIRED OTP
    # =========================================================================
    def test_05_expired_otp_rejection(self):
        """Wait/fast-forward until expiration: OTP rejected with expired notice."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)

        # Force record in database to expired timestamp
        past_time = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        conn = db.get_db_connection()
        conn.execute("UPDATE password_resets SET expires_at = ? WHERE email = ?", (past_time, self.email_a))
        conn.commit()
        conn.close()

        verify_res = client.post("/api/auth/verify-reset-otp", json={
            "email": self.email_a,
            "otp": otp
        })
        self.assertEqual(verify_res.status_code, 400)
        self.assertIn("expired", verify_res.json()["detail"].lower())

    # =========================================================================
    # TEST 6 — REUSE OTP & AUTHORIZATION
    # =========================================================================
    def test_06_reuse_otp_and_authorization_prevention(self):
        """Successfully reset password: OTP and authorization cannot be reused."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)
        v_res = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": otp})
        reset_auth = v_res.json()["reset_authorization"]

        # Reset password successfully
        new_pass = "BrandNewPassword2026!"
        rst_res = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": new_pass,
            "confirm_password": new_pass
        })
        self.assertEqual(rst_res.status_code, 200)

        # 1. Attempt to reuse reset authorization
        reuse_auth = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": "YetAnotherPassword999!",
            "confirm_password": "YetAnotherPassword999!"
        })
        self.assertEqual(reuse_auth.status_code, 400)
        self.assertIn("already been used", reuse_auth.json()["detail"].lower())

        # 2. Attempt to re-verify original OTP
        reuse_otp = client.post("/api/auth/verify-reset-otp", json={
            "email": self.email_a,
            "otp": otp
        })
        self.assertEqual(reuse_otp.status_code, 400)

    # =========================================================================
    # TEST 7 — RESEND OTP
    # =========================================================================
    def test_07_resend_otp_invalidates_old_and_issues_new(self):
        """Request new OTP: old OTP invalidated, new OTP generated and dispatched."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        first_otp = email_service.get_last_otp_for_email(self.email_a)

        # Clear cooldown so resend is permitted
        self._clear_cooldown(self.email_a)

        # Resend OTP
        resend_res = client.post("/api/auth/resend-reset-otp", json={"email": self.email_a})
        self.assertEqual(resend_res.status_code, 200)
        second_otp = email_service.get_last_otp_for_email(self.email_a)

        self.assertNotEqual(first_otp, second_otp, "Resent OTP should be a fresh code.")

        # Attempt to verify the OLD OTP must fail
        old_v = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": first_otp})
        self.assertEqual(old_v.status_code, 400)

        # Verifying the NEW OTP must succeed
        new_v = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": second_otp})
        self.assertEqual(new_v.status_code, 200)

    # =========================================================================
    # TEST 8 — UNKNOWN EMAIL
    # =========================================================================
    def test_08_unknown_email_returns_identical_generic_response(self):
        """Enter email not registered: returns identical generic response, minimizing account enumeration."""
        nonexistent = f"ghost_user_{int(datetime.now().timestamp())}@nowhere.invalid"
        res = client.post("/api/auth/forgot-password", json={"email": nonexistent})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("verification code has been sent", data["message"].lower())

        # Verify no email was dispatched to nonexistent address
        otp = email_service.get_last_otp_for_email(nonexistent)
        self.assertIsNone(otp, "No OTP should be sent for unregistered accounts.")

    # =========================================================================
    # TEST 9 — EMAIL DELIVERY FAILURE
    # =========================================================================
    def test_09_email_delivery_failure_safe_handling(self):
        """Simulate email delivery provider failure: safe error handling, no secrets exposed."""
        orig_send = email_service.send_password_reset_email
        try:
            email_service.send_password_reset_email = lambda email, otp: False

            res = client.post("/api/auth/forgot-password", json={"email": self.email_a})
            self.assertEqual(res.status_code, 500)
            self.assertIn("unable to deliver", res.json()["detail"].lower())
            # Ensure no credentials or OTP leaked in error detail
            self.assertNotIn("password", res.json()["detail"].lower())
        finally:
            email_service.send_password_reset_email = orig_send

    # =========================================================================
    # TEST 10 — PASSWORD MISMATCH
    # =========================================================================
    def test_10_password_mismatch_rejected(self):
        """Password and confirm_password do not match: reset rejected."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)
        v_res = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": otp})
        reset_auth = v_res.json()["reset_authorization"]

        rst_res = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": "NewValidPassword2026!",
            "confirm_password": "DifferentPassword2026!"
        })
        self.assertEqual(rst_res.status_code, 400)
        self.assertIn("do not match", rst_res.json()["detail"].lower())

    # =========================================================================
    # TEST 11 — SHORT PASSWORD
    # =========================================================================
    def test_11_short_password_rejected(self):
        """Password shorter than 8 characters: reset rejected."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)
        v_res = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": otp})
        reset_auth = v_res.json()["reset_authorization"]

        rst_res = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": "short",
            "confirm_password": "short"
        })
        self.assertIn(rst_res.status_code, [400, 422])

    # =========================================================================
    # TEST 12 — DIRECT PASSWORD RESET API CALL
    # =========================================================================
    def test_12_direct_reset_call_without_authorization_rejected(self):
        """Attempt reset without verified reset authorization: rejected."""
        rst_res = client.post("/api/auth/reset-password", json={
            "reset_authorization": "rst-auth-unverified-fake-token",
            "new_password": "NewValidPassword2026!",
            "confirm_password": "NewValidPassword2026!"
        })
        self.assertEqual(rst_res.status_code, 400)
        self.assertIn("invalid", rst_res.json()["detail"].lower())

    # =========================================================================
    # TEST 13 — CROSS-USER ATTACK
    # =========================================================================
    def test_13_cross_user_attack_prevention(self):
        """User A's reset authorization cannot reset User B's password."""
        # Issue authorization for User A
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp_a = email_service.get_last_otp_for_email(self.email_a)
        v_res = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": otp_a})
        reset_auth_a = v_res.json()["reset_authorization"]

        # User A resets password using their authorization
        new_pass_a = "UserANewPassword2026!"
        rst_res = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth_a,
            "new_password": new_pass_a,
            "confirm_password": new_pass_a
        })
        self.assertEqual(rst_res.status_code, 200)

        # Verify User A's password updated
        login_a = client.post("/api/auth/login", json={
            "username_or_email": self.email_a,
            "password": new_pass_a
        })
        self.assertEqual(login_a.status_code, 200)

        # CRITICAL: User B's password MUST NOT have changed!
        login_b_orig = client.post("/api/auth/login", json={
            "username_or_email": self.email_b,
            "password": self.password_orig
        })
        self.assertEqual(login_b_orig.status_code, 200, "User B's original password must remain intact.")

        login_b_new = client.post("/api/auth/login", json={
            "username_or_email": self.email_b,
            "password": new_pass_a
        })
        self.assertEqual(login_b_new.status_code, 401, "User B must not be accessible via User A's new password.")

    # =========================================================================
    # TEST 14 — REFRESH / STATE ISOLATION DURING RESET
    # =========================================================================
    def test_14_consumed_state_cannot_be_reused(self):
        """Consumed or invalidated reset states cannot be reused across flows."""
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)
        v_res = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": otp})
        reset_auth = v_res.json()["reset_authorization"]

        # Consumed via password update
        client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": "NewValidPassword2026!",
            "confirm_password": "NewValidPassword2026!"
        })

        # Fresh attempt using same authorization
        attempt = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": "AnotherNewPassword2026!"
        })
        self.assertEqual(attempt.status_code, 400)

    # =========================================================================
    # TEST 15 — NORMAL LOGIN AFTER RESET
    # =========================================================================
    def test_15_normal_login_after_reset_succeeds_and_revokes_old(self):
        """Reset password successfully: new password works, old password revoked, sessions cleared."""
        # 1. User A logs in with old password to establish a session
        login_old = client.post("/api/auth/login", json={
            "username_or_email": self.email_a,
            "password": self.password_orig
        })
        self.assertEqual(login_old.status_code, 200)
        old_token = login_old.json()["access_token"]

        # Confirm old session works
        me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_token}"})
        self.assertEqual(me_res.status_code, 200)

        # 2. Reset password
        client.post("/api/auth/forgot-password", json={"email": self.email_a})
        otp = email_service.get_last_otp_for_email(self.email_a)
        v_res = client.post("/api/auth/verify-reset-otp", json={"email": self.email_a, "otp": otp})
        reset_auth = v_res.json()["reset_authorization"]

        updated_password = "SuccessPassword2026!"
        rst_res = client.post("/api/auth/reset-password", json={
            "reset_authorization": reset_auth,
            "new_password": updated_password,
            "confirm_password": updated_password
        })
        self.assertEqual(rst_res.status_code, 200)

        # 3. Old session must be revoked
        post_rst_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_token}"})
        self.assertEqual(post_rst_me.status_code, 401, "Active sessions must be revoked upon password reset.")

        # 4. Old password cannot authenticate
        login_failed = client.post("/api/auth/login", json={
            "username_or_email": self.email_a,
            "password": self.password_orig
        })
        self.assertEqual(login_failed.status_code, 401, "Old password must no longer authenticate.")

        # 5. New password authenticates successfully
        login_success = client.post("/api/auth/login", json={
            "username_or_email": self.email_a,
            "password": updated_password
        })
        self.assertEqual(login_success.status_code, 200, "New password must authenticate successfully.")
        self.assertIsNotNone(login_success.json().get("access_token"))


if __name__ == "__main__":
    unittest.main()
