"""Approval orchestration: review opens an approval; approve gates execution;
reject denies; the broker timeout fails closed even if the surface later approves."""

import json
import unittest

from broker import approval
from broker import request_lifecycle as lifecycle
from broker.identity import authenticate

from .support import BrokerTestCase, FakeSurface, seed_caller

CID = "corr-1"


class ApprovalFlow(BrokerTestCase):
    def _setup(self, surface):
        ctx = self.make_ctx(catalog={"echo": {"shout": "high"}}, surface=surface)
        token = seed_caller(ctx.store, "hermes", review=["echo.shout"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        return ctx, caller

    def test_review_opens_approval_and_parks_pending(self):
        surface = FakeSurface(approval.PENDING)
        ctx, caller = self._setup(surface)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {"m": "hi"}, CID)
        self.assertEqual(out.status, lifecycle.PENDING)
        self.assertEqual(len(surface.opened), 1)
        self.assertEqual(ctx.store.request(out.request_id)["status"], "pending_approval")
        # resolving while still pending stays pending and runs nothing
        self.assertEqual(lifecycle.resolve_request(ctx, out.request_id).status, lifecycle.PENDING)
        self.assertEqual(ctx.runtime.calls, [])

    def test_approval_gates_execution(self):
        surface = FakeSurface(approval.PENDING)
        ctx, caller = self._setup(surface)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {"m": "hi"}, CID)
        surface.set(approval.APPROVED, approver="owner")
        resolved = lifecycle.resolve_request(ctx, out.request_id)
        self.assertEqual(resolved.status, lifecycle.OK)
        self.assertEqual(resolved.result, {"echoed": {"m": "hi"}})
        self.assertEqual(ctx.store.request(out.request_id)["status"], "completed")
        self.assertEqual(len(ctx.runtime.calls), 1)
        self.assertIsNone(ctx.store.request(out.request_id)["arguments_json"])  # cleared

    def test_rejection_denies(self):
        surface = FakeSurface(approval.PENDING)
        ctx, caller = self._setup(surface)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {}, CID)
        surface.set(approval.REJECTED, approver="owner", note="no")
        resolved = lifecycle.resolve_request(ctx, out.request_id)
        self.assertEqual(resolved.status, lifecycle.DENIED)
        self.assertEqual(resolved.reason, "approval_rejected")
        self.assertEqual(ctx.runtime.calls, [])
        self.assertEqual(ctx.store.request(out.request_id)["status"], "denied")

    def test_timeout_fails_closed_even_if_surface_says_approved(self):
        surface = FakeSurface(approval.APPROVED, approver="owner")  # surface approves...
        ctx, caller = self._setup(surface)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {}, CID)
        # ...but the broker's deadline has passed -> expired, nothing runs
        resolved = lifecycle.resolve_request(ctx, out.request_id, now=10**12)
        self.assertEqual(resolved.status, lifecycle.EXPIRED)
        self.assertEqual(ctx.runtime.calls, [])
        self.assertEqual(ctx.store.request(out.request_id)["status"], "expired")
        self.assertIn(f"ref-{out.request_id}", surface.cancelled)

    def test_approver_note_surfaced_on_approve(self):
        surface = FakeSurface(approval.APPROVED, approver="alice", note="go ahead")
        ctx, caller = self._setup(surface)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {}, CID)
        resolved = lifecycle.resolve_request(ctx, out.request_id)
        self.assertEqual(resolved.status, lifecycle.OK)
        self.assertEqual(resolved.approver, "alice")
        self.assertEqual(resolved.note, "go ahead")

    def test_agent_reason_rides_to_the_card(self):
        surface = FakeSurface(approval.PENDING)
        ctx, caller = self._setup(surface)
        lifecycle.submit(ctx, caller, "echo", "shout", {}, CID, reason="please skip")
        self.assertEqual(surface.opened[0].justification, "please skip")

    def test_no_surface_is_unavailable(self):
        ctx, caller = self._setup(surface=None)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {}, CID)
        self.assertEqual(out.status, lifecycle.UNAVAILABLE)
        self.assertEqual(ctx.runtime.calls, [])

    def test_arguments_never_audited(self):
        surface = FakeSurface(approval.APPROVED, approver="owner")
        ctx, caller = self._setup(surface)
        out = lifecycle.submit(ctx, caller, "echo", "shout", {"secret": "p@ss"}, CID)
        lifecycle.resolve_request(ctx, out.request_id)
        self.assertNotIn("p@ss", json.dumps(ctx.audit.events()))


class LazySweep(BrokerTestCase):
    """The broker has no background worker, so stale approvals are GC'd lazily:
    `sweep_expired` on demand, and on every `submit`."""

    def _park(self, surface, approval_ttl=3600.0):
        ctx = self.make_ctx(catalog={"echo": {"shout": "high"}},
                            surface=surface, approval_ttl=approval_ttl)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"], review=["echo.shout"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        out = lifecycle.submit(ctx, caller, "echo", "shout", {}, CID)
        return ctx, caller, out

    def test_sweep_expires_stale_pending_approval(self):
        surface = FakeSurface(approval.PENDING)
        ctx, caller, out = self._park(surface)
        n = lifecycle.sweep_expired(ctx, now=10**12)  # far future -> past the deadline
        self.assertEqual(n, 1)
        self.assertEqual(ctx.store.request(out.request_id)["status"], "expired")
        self.assertEqual(ctx.store.approval_for_request(out.request_id)["status"], "expired")
        self.assertIn(f"ref-{out.request_id}", surface.cancelled)
        self.assertEqual(ctx.runtime.calls, [])  # nothing ran

    def test_sweep_leaves_a_live_approval_untouched(self):
        surface = FakeSurface(approval.PENDING)
        ctx, caller, out = self._park(surface)
        self.assertEqual(lifecycle.sweep_expired(ctx), 0)  # now() << deadline
        self.assertEqual(ctx.store.request(out.request_id)["status"], "pending_approval")
        self.assertEqual(surface.cancelled, [])

    def test_submit_triggers_the_sweep(self):
        surface = FakeSurface(approval.PENDING)
        # approval_ttl=0 -> the parked approval's deadline is its creation instant,
        # so it's already stale by the time the next request comes in.
        ctx, caller, out = self._park(surface, approval_ttl=0.0)
        self.assertEqual(ctx.store.request(out.request_id)["status"], "pending_approval")
        # an unrelated new request's lazy GC sweeps the stale one
        lifecycle.submit(ctx, caller, "echo", "say", {}, "corr-2")
        self.assertEqual(ctx.store.request(out.request_id)["status"], "expired")
        self.assertIn(f"ref-{out.request_id}", surface.cancelled)


if __name__ == "__main__":
    unittest.main()
