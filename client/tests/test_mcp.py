"""MCP server: maps broker tools to MCP tools and forwards calls (structured args,
no shell), blocking on approval and surfacing the approver's note."""

import os
import threading
import unittest

from broker import approval
from broker.identity import hash_token
from broker.server import build_server
from broker.tests.support import FakeRuntime, FakeSurface, make_registry
from client import mcp_server


class McpServer(unittest.TestCase):
    def setUp(self):
        self.surface = FakeSurface(approval.PENDING)
        self.server = build_server(
            port=0, db_path=":memory:", audit_sink=None, rate_limit=0,
            registry=make_registry({"echo": {"say": "low", "skip": "high"}}),
            runtime=FakeRuntime(), surface=self.surface,
        )
        port = self.server.server_address[1]
        store = self.server.ctx.store
        caller_id = store.add_caller("hermes")
        store.add_token(caller_id, hash_token("t"))
        store.set_policy(caller_id, {"tools": {"echo": {"say": "allow", "skip": "review"}}})
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        os.environ["TOOLSTACK_URL"] = f"http://127.0.0.1:{port}"
        os.environ["TOOLSTACK_TOKEN"] = "t"
        self.addCleanup(os.environ.pop, "TOOLSTACK_URL", None)
        self.addCleanup(os.environ.pop, "TOOLSTACK_TOKEN", None)
        self.mcp = mcp_server.Server()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.server.ctx.store.close()

    def test_initialize(self):
        r = self.mcp.dispatch("initialize", {"protocolVersion": "2024-11-05"})
        self.assertEqual(r["serverInfo"]["name"], "toolstack")
        self.assertIn("tools", r["capabilities"])

    def test_tools_list_maps_allowed_ops(self):
        tools = {t["name"]: t for t in self.mcp.dispatch("tools/list", {})["tools"]}
        self.assertIn("echo__say", tools)
        self.assertIn("echo__skip", tools)
        self.assertEqual(tools["echo__say"]["inputSchema"]["type"], "object")

    def test_call_allowed(self):
        r = self.mcp.dispatch("tools/call", {"name": "echo__say", "arguments": {"m": "hi"}})
        self.assertFalse(r["isError"])
        self.assertIn("echoed", r["content"][0]["text"])

    def test_call_review_blocks_then_approves_with_note(self):
        self.surface.set(approval.APPROVED, approver="alice", note="ok by me")
        r = self.mcp.dispatch("tools/call", {"name": "echo__skip", "arguments": {}})
        self.assertFalse(r["isError"])
        self.assertIn("alice", r["content"][0]["text"])
        self.assertIn("ok by me", r["content"][0]["text"])

    def test_call_rejected_is_error_with_note(self):
        self.surface.set(approval.REJECTED, approver="alice", note="not now")
        r = self.mcp.dispatch("tools/call", {"name": "echo__skip", "arguments": {}})
        self.assertTrue(r["isError"])
        self.assertIn("denied", r["content"][0]["text"])
        self.assertIn("not now", r["content"][0]["text"])

    def test_call_review_timeout_is_error_not_false_success(self):
        # surface stays PENDING -> the wait times out. The call did not complete,
        # so the result must be isError:true with status=timeout (not a silent pass).
        srv = mcp_server.Server(poll_timeout=0)
        r = srv.dispatch("tools/call", {"name": "echo__skip", "arguments": {}})
        self.assertTrue(r["isError"])
        self.assertIn('"status": "timeout"', r["content"][0]["text"])

    def test_review_schema_advertises_reason_only_on_review(self):
        tools = {t["name"]: t for t in self.mcp.dispatch("tools/list", {})["tools"]}
        # a review op's input schema advertises the optional _reason justification...
        self.assertIn("_reason", tools["echo__skip"]["inputSchema"]["properties"])
        # ...an allow op does not (no human reads it)
        self.assertNotIn("_reason", tools["echo__say"]["inputSchema"].get("properties", {}))

    def test_review_call_forwards_reason_to_approver_and_strips_it(self):
        self.surface.set(approval.APPROVED, approver="alice", note="ok")
        r = self.mcp.dispatch("tools/call",
                              {"name": "echo__skip", "arguments": {"_reason": "skip the ad break"}})
        self.assertFalse(r["isError"])
        # the justification rode to the human on the approval card (redacted)...
        self.assertIn("skip the ad break", self.surface.opened[-1].justification)
        # ...and _reason was NOT forwarded to the tool
        self.assertNotIn("_reason", r["content"][0]["text"])

    def test_review_call_without_reason_sends_none(self):
        self.surface.set(approval.APPROVED, approver="alice", note="ok")
        self.mcp.dispatch("tools/call", {"name": "echo__skip", "arguments": {}})
        self.assertIsNone(self.surface.opened[-1].justification)

    def test_unknown_method_is_jsonrpc_error(self):
        resp = mcp_server._handle(self.mcp, {"jsonrpc": "2.0", "id": 1, "method": "bogus"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_notification_gets_no_response(self):
        self.assertIsNone(
            mcp_server._handle(self.mcp, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        )


if __name__ == "__main__":
    unittest.main()
