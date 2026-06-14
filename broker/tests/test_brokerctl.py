"""brokerctl operator flows: create/revoke callers, edit policy, revoke tokens,
and that mutating actions are recorded as admin.* audit events."""

import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from broker import brokerctl
from broker.identity import authenticate, hash_token
from broker.store import Store


class Brokerctl(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        self.addCleanup(os.unlink, self.db)

    def _run(self, func, **kw):
        kw.setdefault("db", self.db)
        kw.setdefault("operator", "op")
        out = io.StringIO()
        with redirect_stdout(out):
            func(argparse.Namespace(**kw))
        return out.getvalue()

    def _token(self, output):
        return output.strip().splitlines()[-1]

    def _store(self):
        store = Store(self.db)
        self.addCleanup(store.close)
        return store

    def test_create_caller_authenticates_and_is_audited(self):
        out = self._run(brokerctl.create_caller, name="hermes", allow=["echo.say"], review=None)
        token = self._token(out)
        store = self._store()
        caller = authenticate(store, f"Bearer {token}")
        self.assertIsNotNone(caller)
        self.assertEqual(store.policy_for(caller.id), {"tools": {"echo": {"say": "allow"}}})
        self.assertTrue(any(e["component"] == "admin" and e["event_type"] == "caller_created"
                            for e in store.audit_events()))

    def test_revoke_token_denies_next_auth(self):
        token = self._token(self._run(brokerctl.create_caller, name="hermes", allow=["echo.say"], review=None))
        store = self._store()
        self.assertIsNotNone(authenticate(store, f"Bearer {token}"))
        self._run(brokerctl.revoke_token, prefix=hash_token(token)[:12])
        self.assertIsNone(authenticate(store, f"Bearer {token}"))

    def test_revoke_caller_denies_next_auth(self):
        token = self._token(self._run(brokerctl.create_caller, name="hermes", allow=["echo.say"], review=None))
        self._run(brokerctl.revoke_caller, name="hermes")
        self.assertIsNone(authenticate(self._store(), f"Bearer {token}"))

    def test_set_and_show_policy(self):
        self._run(brokerctl.create_caller, name="hermes", allow=None, review=None)
        self._run(brokerctl.set_policy, name="hermes", allow=["echo.say"], review=["echo.skip"])
        shown = self._run(brokerctl.show_policy, name="hermes")
        self.assertIn("echo", shown)
        self.assertIn("review", shown)

    def test_audit_command_shows_admin_events(self):
        self._run(brokerctl.create_caller, name="hermes", allow=["echo.say"], review=None)
        out = self._run(brokerctl.audit, request_id=None, correlation_id=None, limit=50)
        self.assertIn("admin.caller_created", out)

    def test_unknown_caller_errors(self):
        with self.assertRaises(SystemExit):
            self._run(brokerctl.revoke_caller, name="ghost")


if __name__ == "__main__":
    unittest.main()
