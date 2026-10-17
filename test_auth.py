"""QM-5: unit tests derived from the Gherkin acceptance criteria."""
import time
import unittest

import auth_service as a

EMAIL = "alice@example.com"
PASSWORD = "S3cure-passw0rd!"


class TestRegistration(unittest.TestCase):
    def setUp(self):
        a.reset()

    def test_successful_registration_returns_201_pending(self):
        r = a.register_user(EMAIL, PASSWORD)
        self.assertEqual(r, {"status": "pending_verification", "http": 201})
        self.assertFalse(a.is_verified(EMAIL))

    def test_verification_email_is_queued_with_token(self):
        a.register_user(EMAIL, PASSWORD)
        self.assertEqual(len(a.OUTBOX), 1)
        self.assertEqual(a.OUTBOX[0]["to"], EMAIL)
        self.assertTrue(a.OUTBOX[0]["token"])

    def test_duplicate_registration_is_rejected_409(self):
        a.register_user(EMAIL, PASSWORD)
        with self.assertRaises(a.DuplicateUserError):
            a.register_user(EMAIL, "An0ther-passw0rd!")

    def test_short_password_is_rejected(self):
        with self.assertRaises(ValueError):
            a.register_user("bob@example.com", "short")

    def test_password_is_hashed_not_stored_in_plaintext(self):
        a.register_user(EMAIL, PASSWORD)
        self.assertNotIn(PASSWORD.encode(), a.stored_hash(EMAIL))

    def test_valid_token_verifies_account(self):
        a.register_user(EMAIL, PASSWORD)
        r = a.verify_token(a.OUTBOX[0]["token"])
        self.assertEqual(r["status"], "verified")
        self.assertTrue(a.is_verified(EMAIL))

    def test_expired_token_is_rejected(self):
        a.register_user(EMAIL, PASSWORD)
        token = a.create_verification_token(EMAIL, now=time.time() - 2 * a.TOKEN_TTL_SECONDS)
        with self.assertRaises(a.ExpiredTokenError):
            a.verify_token(token)
        self.assertFalse(a.is_verified(EMAIL))

    def test_tampered_token_is_rejected(self):
        a.register_user(EMAIL, PASSWORD)
        with self.assertRaises(a.InvalidTokenError):
            a.verify_token(a.OUTBOX[0]["token"][:-4] + "AAAA")


if __name__ == "__main__":
    unittest.main()
