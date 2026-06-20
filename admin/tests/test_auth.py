"""admin.auth: password hashing, signed sessions, and CSRF tokens, all stdlib.
Round-trips succeed; wrong secrets, tampering, and expiry all fail closed."""

import unittest

from admin import auth


class Password(unittest.TestCase):
    def test_hash_verify_roundtrip(self):
        h = auth.hash_password("correct horse battery staple")
        self.assertTrue(auth.verify_password("correct horse battery staple", h))
        self.assertFalse(auth.verify_password("wrong", h))

    def test_hash_is_salted(self):
        self.assertNotEqual(auth.hash_password("x"), auth.hash_password("x"))

    def test_verify_rejects_garbage(self):
        self.assertFalse(auth.verify_password("x", "not-a-valid-hash"))


class Session(unittest.TestCase):
    SECRET = "session-secret"

    def test_roundtrip(self):
        cookie = auth.sign_session("admin", self.SECRET, ttl_seconds=60)
        self.assertEqual(auth.verify_session(cookie, self.SECRET), "admin")

    def test_wrong_secret_rejected(self):
        cookie = auth.sign_session("admin", self.SECRET, ttl_seconds=60)
        self.assertIsNone(auth.verify_session(cookie, "other-secret"))

    def test_expired_rejected(self):
        cookie = auth.sign_session("admin", self.SECRET, ttl_seconds=-1)
        self.assertIsNone(auth.verify_session(cookie, self.SECRET))

    def test_tampered_rejected(self):
        cookie = auth.sign_session("admin", self.SECRET, ttl_seconds=60)
        self.assertIsNone(auth.verify_session(cookie + "x", self.SECRET))

    def test_none_rejected(self):
        self.assertIsNone(auth.verify_session(None, self.SECRET))


class Csrf(unittest.TestCase):
    SECRET = "session-secret"

    def test_token_verifies(self):
        session = auth.sign_session("admin", self.SECRET, 60)
        token = auth.csrf_token(session, self.SECRET)
        self.assertTrue(auth.verify_csrf(token, session, self.SECRET))

    def test_token_bound_to_session(self):
        s1 = auth.sign_session("admin", self.SECRET, 60)
        s2 = auth.sign_session("admin", self.SECRET, 120)  # different expiry -> different cookie
        self.assertFalse(auth.verify_csrf(auth.csrf_token(s1, self.SECRET), s2, self.SECRET))

    def test_missing_inputs_rejected(self):
        self.assertFalse(auth.verify_csrf(None, "sess", self.SECRET))
        self.assertFalse(auth.verify_csrf("tok", None, self.SECRET))


if __name__ == "__main__":
    unittest.main()
