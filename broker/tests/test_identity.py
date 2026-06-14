"""Identity: bearer parsing, token hashing, and fail-closed authentication."""

import unittest

from broker.identity import authenticate, bearer_token, hash_token
from broker.store import Store


class BearerParsing(unittest.TestCase):
    def test_extraction(self):
        self.assertEqual(bearer_token("Bearer abc"), "abc")
        self.assertEqual(bearer_token("bearer abc"), "abc")  # scheme case-insensitive
        self.assertIsNone(bearer_token(None))
        self.assertIsNone(bearer_token("Basic abc"))
        self.assertIsNone(bearer_token("Bearer "))


class Authenticate(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.caller_id = self.store.add_caller("hermes")
        self.token = "secret-token"
        self.store.add_token(self.caller_id, hash_token(self.token))

    def tearDown(self):
        self.store.close()

    def test_valid_token_resolves_caller(self):
        caller = authenticate(self.store, f"Bearer {self.token}")
        self.assertIsNotNone(caller)
        self.assertEqual(caller.name, "hermes")

    def test_unknown_token_denied(self):
        self.assertIsNone(authenticate(self.store, "Bearer nope"))

    def test_absent_header_denied(self):
        self.assertIsNone(authenticate(self.store, None))

    def test_revoked_token_denied_immediately(self):
        self.store.revoke_token(hash_token(self.token))
        self.assertIsNone(authenticate(self.store, f"Bearer {self.token}"))

    def test_revoked_caller_denied_immediately(self):
        self.store.revoke_caller("hermes")
        self.assertIsNone(authenticate(self.store, f"Bearer {self.token}"))

    def test_token_stored_only_as_hash(self):
        rows = self.store._conn.execute("SELECT token_hash FROM tokens").fetchall()
        hashes = [r["token_hash"] for r in rows]
        self.assertNotIn(self.token, hashes)  # raw token never persisted
        self.assertEqual(hashes, [hash_token(self.token)])


if __name__ == "__main__":
    unittest.main()
