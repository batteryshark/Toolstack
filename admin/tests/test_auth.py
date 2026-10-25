"""admin.auth: password hashing, signed sessions, and CSRF tokens, all stdlib.
Round-trips succeed; wrong secrets, tampering, and expiry all fail closed."""

import base64
import hashlib
import hmac
import time
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

    def test_wrong_purpose_and_legacy_signatures_rejected(self):
        expiry = str(int(time.time()) + 60)
        # This demonstrates a domain collision, not a pre-auth token oracle.
        for username, signature in (
            ("csrf", auth.csrf_token(expiry, self.SECRET)),
            ("csrf-v1", auth.csrf_token(expiry, self.SECRET)),
            ("csrf", hmac.new(self.SECRET.encode(), ("csrf|" + expiry).encode(), hashlib.sha256).hexdigest()),
            ("admin", hmac.new(self.SECRET.encode(), ("admin|" + expiry).encode(), hashlib.sha256).hexdigest()),
        ):
            cookie = base64.urlsafe_b64encode(f"{username}|{expiry}|{signature}".encode()).decode()
            with self.subTest(username=username, signature=signature):
                self.assertIsNone(auth.verify_session(cookie, self.SECRET))

    def test_malformed_inputs_fail_closed(self):
        malformed = base64.urlsafe_b64encode(f"admin|{int(time.time()) + 60}|é".encode()).decode()
        for cookie in (malformed, "é", "\ud800", 42, b"cookie", [], {}, None):
            with self.subTest(cookie=cookie):
                self.assertIsNone(auth.verify_session(cookie, self.SECRET))


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

    def test_malformed_inputs_fail_closed(self):
        for value in ("é", "\ud800", 42, b"token", [], {}, None):
            with self.subTest(value=value):
                self.assertFalse(auth.verify_csrf(value, "sess", self.SECRET))
                self.assertFalse(auth.verify_csrf("token", value, self.SECRET))

    def test_legacy_csrf_and_session_signature_rejected(self):
        session = auth.sign_session("admin", self.SECRET, 60)
        legacy = hmac.new(self.SECRET.encode(), ("csrf|" + session).encode(), hashlib.sha256).hexdigest()
        signature = base64.urlsafe_b64decode(session).decode().rsplit("|", 1)[1]
        self.assertFalse(auth.verify_csrf(legacy, session, self.SECRET))
        self.assertFalse(auth.verify_csrf(signature, session, self.SECRET))


if __name__ == "__main__":
    unittest.main()
