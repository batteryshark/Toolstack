"""Broker-native MCP endpoint (POST /mcp): JSON-RPC framing terminated at the broker,
routed through the SAME auth / policy / approval / audit as the REST /v1/actions path.

These go through the real gateway `handle(...)` so they prove the whole ingress: a bearer
token is required, discovery is policy-filtered, an allow op executes end to end, and a
review op parks (non-blocking) and resolves through the same poll the REST caller uses.
"""

import json
import unittest

from broker import approval
from broker.gateway import handle
from broker.ratelimit import RateLimiter

from .support import BrokerTestCase, FakeSurface, seed_caller

CATALOG = {"echo": {"say": "low", "shout": "high", "secret": "high"}}


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _mcp(ctx, token, method, params=None, mid=1):
    msg = {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}
    return handle("POST", "/mcp", _bearer(token), msg, ctx)


def _tool_result(response):
    """The MCP tool result inside a JSON-RPC response: (parsed-text-body, is_error)."""
    result = response.body["result"]
    return json.loads(result["content"][0]["text"]), result["isError"]


class Auth(BrokerTestCase):
    def test_unauthenticated_mcp_is_401(self):
        # Same boundary as REST: only GET /v1/health is open; /mcp needs a token.
        r = handle("POST", "/mcp", {}, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, self.make_ctx())
        self.assertEqual(r.status, 401)

    def test_bad_token_is_401(self):
        r = _mcp(self.make_ctx(catalog=CATALOG), "nope", "ping")
        self.assertEqual(r.status, 401)


class Handshake(BrokerTestCase):
    def setUp(self):
        self.ctx = self.make_ctx(catalog=CATALOG)
        self.token = seed_caller(self.ctx.store, "hermes", allow=["echo.say"])

    def test_initialize(self):
        r = _mcp(self.ctx, self.token, "initialize", {"protocolVersion": "2024-11-05"})
        self.assertEqual(r.status, 200)
        result = r.body["result"]
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertEqual(result["serverInfo"]["name"], "toolstack-broker")
        self.assertIn("tools", result["capabilities"])

    def test_ping(self):
        self.assertEqual(_mcp(self.ctx, self.token, "ping").body["result"], {})

    def test_unknown_method_is_jsonrpc_error(self):
        r = _mcp(self.ctx, self.token, "bogus")
        self.assertEqual(r.status, 200)  # JSON-RPC errors ride a 200 envelope
        self.assertEqual(r.body["error"]["code"], -32601)

    def test_params_not_object_is_invalid_params(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": 7}
        r = handle("POST", "/mcp", _bearer(self.token), msg, self.ctx)
        self.assertEqual(r.body["error"]["code"], -32602)

    def test_notification_gets_empty_response(self):
        # No id => a notification: no JSON-RPC response body.
        msg = {"jsonrpc": "2.0", "method": "ping"}
        r = handle("POST", "/mcp", _bearer(self.token), msg, self.ctx)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, {})

    def test_malformed_json_body_is_parse_error(self):
        # The server hands the gateway None for a body that wasn't valid JSON.
        r = handle("POST", "/mcp", _bearer(self.token), None, self.ctx)
        self.assertEqual(r.body["error"]["code"], -32700)

    def test_batch_is_unsupported(self):
        msg = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}]
        r = handle("POST", "/mcp", _bearer(self.token), msg, self.ctx)
        self.assertEqual(r.body["error"]["code"], -32600)
        self.assertIn("batch", r.body["error"]["message"])


class ToolsList(BrokerTestCase):
    def test_lists_only_allowed_ops_with_schemas(self):
        ctx = self.make_ctx(catalog=CATALOG)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"], review=["echo.shout"])
        tools = {t["name"]: t for t in _mcp(ctx, token, "tools/list").body["result"]["tools"]}

        self.assertIn("echo__say", tools)
        self.assertIn("echo__shout", tools)
        self.assertNotIn("echo__secret", tools)  # denied -> omitted (least privilege)

    def test_review_op_advertises_reason_and_approval_note(self):
        ctx = self.make_ctx(catalog=CATALOG)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"], review=["echo.shout"])
        tools = {t["name"]: t for t in _mcp(ctx, token, "tools/list").body["result"]["tools"]}

        self.assertIn("_reason", tools["echo__shout"]["inputSchema"]["properties"])
        self.assertTrue(tools["echo__shout"]["description"].endswith("(requires human approval)"))
        # an allow op carries neither
        self.assertNotIn("_reason", tools["echo__say"].get("inputSchema", {}).get("properties", {}))


class ToolsCall(BrokerTestCase):
    def setUp(self):
        self.ctx = self.make_ctx(catalog=CATALOG)
        self.token = seed_caller(
            self.ctx.store, "hermes", allow=["echo.say"], review=["echo.shout"])

    def _call(self, name, arguments=None, mid=1):
        return _mcp(self.ctx, self.token, "tools/call",
                    {"name": name, "arguments": arguments or {}}, mid)

    def test_allow_executes_and_returns_result(self):
        body, is_error = _tool_result(self._call("echo__say", {"m": "hi"}))
        self.assertFalse(is_error)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["result"], {"echoed": {"m": "hi"}})
        self.assertEqual(self.ctx.runtime.calls[0][:3], ("echo", "say", {"m": "hi"}))

    def test_allow_emits_same_terminal_audit_as_rest(self):
        self._call("echo__say", {"m": "hi"})
        terminal = [e for e in self.ctx.audit.events()
                    if e["component"] == "request" and e["event_type"] == "completed"]
        self.assertEqual(len(terminal), 1)  # one request.completed, exactly like REST

    def test_unknown_tool_is_error_result_and_is_audited(self):
        result = self._call("echo__ghost").body["result"]
        self.assertTrue(result["isError"])
        self.assertIn("unknown tool", result["content"][0]["text"])
        # the probe is audited like REST's registry.tool_lookup_failed (not silently dropped)
        pairs = [(e["component"], e["event_type"]) for e in self.ctx.audit.events()]
        self.assertIn(("registry", "tool_lookup_failed"), pairs)

    def test_denied_op_is_hidden_in_result_but_audited_like_rest(self):
        # echo.secret is registered but not granted. Least privilege hides "denied" from the
        # caller (reads as "unknown"), but the denial is still recorded; the same
        # policy.decision_deny + request.denied trail REST writes, so a probe stays queryable.
        result = self._call("echo__secret").body["result"]
        self.assertTrue(result["isError"])
        self.assertIn("unknown tool", result["content"][0]["text"])
        pairs = [(e["component"], e["event_type"]) for e in self.ctx.audit.events()]
        self.assertIn(("policy", "decision_deny"), pairs)
        self.assertIn(("request", "denied"), pairs)

    def test_reason_is_stripped_from_tool_arguments(self):
        # `_reason` is adapter metadata, never a tool argument, even on an allow op.
        self._call("echo__say", {"m": "hi", "_reason": "because"})
        self.assertEqual(self.ctx.runtime.calls[0][2], {"m": "hi"})

    def test_review_parks_nonblocking_then_resolves_like_rest(self):
        surface = FakeSurface(approval.PENDING)
        ctx = self.make_ctx(catalog={"echo": {"shout": "high"}}, surface=surface)
        token = seed_caller(ctx.store, "hermes", review=["echo.shout"])

        # the MCP call returns immediately with pending_approval (does NOT block)
        call = _mcp(ctx, token, "tools/call",
                    {"name": "echo__shout", "arguments": {"m": "hi", "_reason": "please review"}})
        body, is_error = _tool_result(call)
        self.assertFalse(is_error)  # pending is in-progress, not an error
        self.assertEqual(body["status"], "pending_approval")
        rid = body["request_id"]
        self.assertEqual(ctx.runtime.calls, [])  # tool has NOT run yet

        # the agent's reason rode to the human approver (redacted), as on the REST path
        self.assertIn("please review", surface.opened[0].justification)

        # resolution uses the very same poll a REST caller uses
        surface.set(approval.APPROVED, approver="owner")
        poll = handle("GET", f"/v1/requests/{rid}", _bearer(token), {}, ctx)
        self.assertEqual(poll.body["status"], "ok")
        self.assertEqual(poll.body["result"], {"echoed": {"m": "hi"}})
        self.assertEqual(ctx.runtime.calls[0][2], {"m": "hi"})  # ran with _reason stripped


class RateLimit(BrokerTestCase):
    def test_tools_call_is_metered_but_handshake_is_not(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "low"}})
        ctx.rate_limiter = RateLimiter(1)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])

        first = _mcp(ctx, token, "tools/call", {"name": "echo__say", "arguments": {}})
        self.assertEqual(first.status, 200)
        self.assertFalse(first.body["result"]["isError"])

        # over the limit -> HTTP 429 (like REST), a JSON-RPC error rather than a tool result
        second = _mcp(ctx, token, "tools/call", {"name": "echo__say", "arguments": {}})
        self.assertEqual(second.status, 429)
        self.assertIn("rate_limited", second.body["error"]["message"])
        # the throttle is queryable in audit with the real outcome (parity with REST's 429)
        outcomes = [(e["component"], e["event_type"], e["outcome"]) for e in ctx.audit.events()]
        self.assertIn(("gateway", "response_returned", "rate_limited"), outcomes)

        # discovery / handshake are not metered (mirrors GET /v1/tools being unmetered)
        self.assertEqual(_mcp(ctx, token, "tools/list").status, 200)
        self.assertEqual(_mcp(ctx, token, "ping").body["result"], {})


if __name__ == "__main__":
    unittest.main()
