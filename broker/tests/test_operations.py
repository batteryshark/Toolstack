"""broker.operations — the operator mutations shared by brokerctl and the admin
web app. Each mutation must persist its effect and record exactly one admin.*
audit event; a missing caller must raise LookupError (not SystemExit) so each
caller can choose how to surface it."""

import unittest

from broker import operations
from broker.identity import authenticate, hash_token
from broker.store import Store

from .support import FakeSurface


class Operations(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def _admin_events(self, event_type):
        return [e for e in self.store.audit_events()
                if e["component"] == "admin" and e["event_type"] == event_type]

    def test_build_policy_allow_overrides_review(self):
        policy = operations.build_policy(allow=["echo.say"], review=["echo.say", "echo.skip"])
        self.assertEqual(policy, {"tools": {"echo": {"say": "allow", "skip": "review"}}})

    def test_build_policy_empty(self):
        self.assertEqual(operations.build_policy(None, None), {"tools": {}})

    def test_create_caller_returns_working_token_and_audits(self):
        token = operations.create_caller(self.store, "hermes", ["echo.say"], None, "op")
        caller = authenticate(self.store, f"Bearer {token}")
        self.assertIsNotNone(caller)
        self.assertEqual(self.store.policy_for(caller.id), {"tools": {"echo": {"say": "allow"}}})
        self.assertEqual(len(self._admin_events("caller_created")), 1)

    def test_issue_token_adds_working_token_and_audits(self):
        operations.create_caller(self.store, "hermes", None, None, "op")
        token = operations.issue_token(self.store, "hermes", "op")
        self.assertIsNotNone(authenticate(self.store, f"Bearer {token}"))
        self.assertEqual(len(self._admin_events("token_issued")), 1)

    def test_revoke_token_denies_next_auth_and_audits(self):
        token = operations.create_caller(self.store, "hermes", ["echo.say"], None, "op")
        self.assertIsNotNone(authenticate(self.store, f"Bearer {token}"))
        count = operations.revoke_token(self.store, hash_token(token)[:12], "op")
        self.assertEqual(count, 1)
        self.assertIsNone(authenticate(self.store, f"Bearer {token}"))
        self.assertEqual(len(self._admin_events("token_revoked")), 1)

    def test_revoke_caller_denies_next_auth_and_audits(self):
        token = operations.create_caller(self.store, "hermes", ["echo.say"], None, "op")
        operations.revoke_caller(self.store, "hermes", "op")
        self.assertIsNone(authenticate(self.store, f"Bearer {token}"))
        self.assertEqual(len(self._admin_events("caller_revoked")), 1)

    def test_set_policy_updates_and_audits(self):
        operations.create_caller(self.store, "hermes", None, None, "op")
        operations.set_policy(self.store, "hermes", ["echo.say"], ["echo.skip"], "op")
        caller = self.store.caller_by_name("hermes")
        self.assertEqual(self.store.policy_for(caller["id"]),
                         {"tools": {"echo": {"say": "allow", "skip": "review"}}})
        self.assertEqual(len(self._admin_events("policy_changed")), 1)

    def test_missing_caller_raises_lookup_error(self):
        for call in (
            lambda: operations.revoke_caller(self.store, "ghost", "op"),
            lambda: operations.set_policy(self.store, "ghost", None, None, "op"),
            lambda: operations.issue_token(self.store, "ghost", "op"),
            lambda: operations.require_caller(self.store, "ghost"),
        ):
            with self.assertRaises(LookupError):
                call()

    def test_revoke_unknown_token_is_noop_without_audit(self):
        count = operations.revoke_token(self.store, "deadbeef", "op")
        self.assertEqual(count, 0)
        self.assertEqual(self._admin_events("token_revoked"), [])

    # --- revocation cancels pending approvals (T-003) -----------------------

    def _seed_pending_approval(self, caller_id, ref="ref-1", expires_at=10**12):
        """A parked, still-live pending approval for a caller (far-future deadline)."""
        rid = self.store.create_request("corr-a", caller_id, "echo", "shout", "pending_approval")
        self.store.create_approval(rid, ref, expires_at)
        return rid

    def _cancel_events(self):
        return [e for e in self.store.audit_events()
                if e["component"] == "approval" and e["event_type"] == "cancelled"]

    def test_revoke_caller_cancels_pending_approvals_and_withdraws(self):
        operations.create_caller(self.store, "hermes", None, None, "op")
        rid = self._seed_pending_approval(self.store.caller_by_name("hermes")["id"])
        surface = FakeSurface()
        cancelled = operations.revoke_caller(self.store, "hermes", "op", surface=surface)
        self.assertEqual(cancelled, 1)
        self.assertEqual(self.store.approval_for_request(rid)["status"], "cancelled")
        self.assertEqual(self.store.request(rid)["status"], "expired")  # disarmed
        self.assertIsNone(self.store.request(rid)["arguments_json"])
        self.assertIn("ref-1", surface.cancelled)  # withdrawn from the surface
        self.assertEqual(len(self._cancel_events()), 1)

    def test_revoke_caller_disarms_even_without_a_surface(self):
        # brokerctl / the admin app revoke out of the broker process and may hold no
        # surface; the store marking alone must guarantee the request can't execute.
        operations.create_caller(self.store, "hermes", None, None, "op")
        rid = self._seed_pending_approval(self.store.caller_by_name("hermes")["id"])
        self.assertEqual(operations.revoke_caller(self.store, "hermes", "op"), 1)  # surface=None
        self.assertEqual(self.store.request(rid)["status"], "expired")
        self.assertEqual(self.store.approval_for_request(rid)["status"], "cancelled")

    def test_revoke_token_cancels_only_when_caller_left_tokenless(self):
        t1 = operations.create_caller(self.store, "hermes", None, None, "op")
        rid = self._seed_pending_approval(self.store.caller_by_name("hermes")["id"])
        t2 = operations.issue_token(self.store, "hermes", "op")  # caller now has 2 tokens
        # one token still live -> the approval stands
        operations.revoke_token(self.store, hash_token(t1)[:16], "op", surface=FakeSurface())
        self.assertEqual(self.store.request(rid)["status"], "pending_approval")
        # last token revoked -> caller de-authenticated -> approval cancelled
        surface = FakeSurface()
        operations.revoke_token(self.store, hash_token(t2)[:16], "op", surface=surface)
        self.assertEqual(self.store.request(rid)["status"], "expired")
        self.assertEqual(self.store.approval_for_request(rid)["status"], "cancelled")
        self.assertIn("ref-1", surface.cancelled)

    def test_revoke_caller_with_no_pending_approvals_is_clean(self):
        operations.create_caller(self.store, "hermes", None, None, "op")
        self.assertEqual(operations.revoke_caller(self.store, "hermes", "op"), 0)
        self.assertEqual(self._cancel_events(), [])

    def test_revoke_token_empty_prefix_is_refused(self):
        # an empty prefix LIKE-matches every token — must not nuke them all
        token = operations.create_caller(self.store, "hermes", None, None, "op")
        self.assertEqual(operations.revoke_token(self.store, "", "op"), 0)
        self.assertIsNotNone(authenticate(self.store, f"Bearer {token}"))  # still live
        self.assertEqual(self._admin_events("token_revoked"), [])


if __name__ == "__main__":
    unittest.main()
