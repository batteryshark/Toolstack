"""Request lifecycle: allow / deny / review / unknown / tool-failure, with
persisted status transitions and no argument leakage into audit."""

import json
import unittest

from broker import request_lifecycle as lifecycle
from broker.identity import authenticate

from .support import BrokerTestCase, seed_caller

CID = "corr-1"


class Submit(BrokerTestCase):
    def _setup(self, catalog=None, runtime=None, allow=None, review=None):
        ctx = self.make_ctx(catalog=catalog, runtime=runtime)
        token = seed_caller(ctx.store, "hermes", allow=allow, review=review)
        caller = authenticate(ctx.store, f"Bearer {token}")
        return ctx, caller

    def test_allow_runs_stub_and_completes(self):
        ctx, caller = self._setup(catalog={"echo": {"say": "low"}}, allow=["echo.say"])
        out = lifecycle.submit(ctx, caller, "echo", "say", {"msg": "hi"}, CID)
        self.assertEqual(out.status, lifecycle.OK)
        self.assertEqual(out.result, {"echoed": {"msg": "hi"}})
        self.assertEqual(ctx.store.request(out.request_id)["status"], "completed")

    def test_default_deny(self):
        # tool is registered, but the caller's policy does not grant it
        ctx, caller = self._setup(catalog={"echo": {"say": "low"}}, allow=[])
        out = lifecycle.submit(ctx, caller, "echo", "say", {}, CID)
        self.assertEqual(out.status, lifecycle.DENIED)
        self.assertEqual(ctx.store.request(out.request_id)["status"], "denied")

    def test_review_parks_pending(self):
        ctx, caller = self._setup(
            catalog={"echo": {"shout": "low"}}, review=["echo.shout"]
        )
        out = lifecycle.submit(ctx, caller, "echo", "shout", {}, CID)
        self.assertEqual(out.status, lifecycle.PENDING)
        self.assertEqual(ctx.store.request(out.request_id)["status"], "pending_approval")

    def test_unknown_tool_is_not_found_without_a_request_row(self):
        ctx, caller = self._setup(catalog={"echo": {"say": "low"}}, allow=["echo.say"])
        out = lifecycle.submit(ctx, caller, "ghost", "go", {}, CID)
        self.assertEqual(out.status, lifecycle.NOT_FOUND)
        self.assertIsNone(out.request_id)

    def test_tool_failure_maps_to_failed(self):
        # Registered, the tool ran but raised -> a generic tool_failed.
        ctx, caller = self._setup(catalog={"boom": {"now": "low"}}, allow=["boom.now"])
        out = lifecycle.submit(ctx, caller, "boom", "now", {}, CID)
        self.assertEqual(out.status, lifecycle.FAILED)
        self.assertEqual(out.error, "tool_failed")
        self.assertIn("RuntimeError", out.detail)
        self.assertEqual(ctx.store.request(out.request_id)["status"], "failed")

    def test_unreachable_tool_maps_to_tool_unreachable(self):
        # The broker couldn't reach the tool (process not running) -> a distinct, diagnostic
        # error so the caller knows to start it, not a generic tool_failed.
        ctx, caller = self._setup(catalog={"down": {"now": "low"}}, allow=["down.now"])
        out = lifecycle.submit(ctx, caller, "down", "now", {}, CID)
        self.assertEqual(out.status, lifecycle.FAILED)
        self.assertEqual(out.error, "tool_unreachable")
        self.assertIn("ToolUnreachable", out.detail)

    def test_arguments_never_appear_in_audit(self):
        ctx, caller = self._setup(catalog={"echo": {"say": "low"}}, allow=["echo.say"])
        lifecycle.submit(ctx, caller, "echo", "say", {"secret": "p@ss"}, CID)
        blob = json.dumps(ctx.audit.events())
        self.assertNotIn("p@ss", blob)

    def test_audit_trail_answers_the_questions(self):
        ctx, caller = self._setup(catalog={"echo": {"say": "low"}}, allow=["echo.say"])
        out = lifecycle.submit(ctx, caller, "echo", "say", {}, CID)
        types = {e["event_type"] for e in ctx.store.audit_events(request_id=out.request_id)}
        self.assertIn("received", types)  # what the agent asked for
        self.assertIn("decision_allow", types)  # what was decided
        self.assertIn("execution_completed", types)  # what actually ran

    def test_rest_audit_event_includes_outbound_metadata_without_body(self):
        class RestRuntime:
            def execute(self, tool_op, arguments, request_id, caller_name):
                return {"status": 202, "headers": {}, "body": "accepted"}

        meta = {
            "verb": "POST",
            "path_template": "/users/{user_id}",
            "base_url_host": "api.example.test",
            "body_kind": "text",
        }
        ctx = self.make_ctx(catalog={"jira": {"create_user": "write"}}, runtime=RestRuntime(),
                            tool_type="rest", rest_meta=meta)
        token = seed_caller(ctx.store, "hermes", allow=["jira.create_user"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        out = lifecycle.submit(
            ctx, caller, "jira", "create_user",
            {"variables": {"user_id": "secret-user"}, "body": '{"password":"p@ss"}'}, CID,
        )
        events = ctx.store.audit_events(request_id=out.request_id)
        completed = [e for e in events if e["component"] == "runtime" and e["event_type"] == "execution_completed"][0]
        details = completed["details"]
        self.assertEqual(details["outbound_host"], "api.example.test")
        self.assertEqual(details["outbound_verb"], "POST")
        self.assertEqual(details["outbound_path_template"], "/users/{user_id}")
        self.assertEqual(details["outbound_status"], 202)
        blob = json.dumps(events)
        self.assertNotIn("secret-user", blob)
        self.assertNotIn("p@ss", blob)


if __name__ == "__main__":
    unittest.main()
