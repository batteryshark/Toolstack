"""HttpRuntime: forwards approved api and mcp calls with broker context,
returns the tool result, and raises (-> 502) when the tool is unreachable."""

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from broker.registry import ToolOp
from broker.runtime import HttpRuntime, _env_tool_secret


class _FakeTool(BaseHTTPRequestHandler):
    received = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        type(self).received = {
            "path": self.path,
            "body": body,
            "shared_secret": self.headers.get("X-Toolstack-Secret"),
        }
        payload = json.dumps({"ok": True, "saw": body}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class Forward(unittest.TestCase):
    def setUp(self):
        _FakeTool.received = None
        self.server = HTTPServer(("127.0.0.1", 0), _FakeTool)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def test_forwards_with_context_and_returns_result(self):
        tool_op = ToolOp("echo", "say", "low", self.port, "api")
        result = HttpRuntime().execute(tool_op, {"m": "hi"}, 7, "hermes")

        self.assertEqual(_FakeTool.received["path"], "/v1/actions/say")
        sent = _FakeTool.received["body"]
        self.assertEqual(sent["arguments"], {"m": "hi"})
        self.assertEqual(sent["broker_request_id"], 7)
        self.assertEqual(sent["caller"], {"name": "hermes"})
        self.assertTrue(result["ok"])

    def test_unreachable_tool_raises(self):
        tool_op = ToolOp("echo", "say", "low", 1, "api")  # nothing listening on :1
        with self.assertRaises(RuntimeError):
            HttpRuntime(timeout=2).execute(tool_op, {}, 1, "hermes")

    def test_sends_shared_secret_header_when_configured(self):
        tool_op = ToolOp("echo", "say", "low", self.port, "api")
        rt = HttpRuntime(tool_secret=lambda tool_id: "sekret" if tool_id == "echo" else None)
        rt.execute(tool_op, {}, 1, "hermes")
        self.assertEqual(_FakeTool.received["shared_secret"], "sekret")

    def test_omits_shared_secret_header_when_unconfigured(self):
        tool_op = ToolOp("echo", "say", "low", self.port, "api")
        rt = HttpRuntime(tool_secret=lambda tool_id: None)
        rt.execute(tool_op, {}, 1, "hermes")
        self.assertIsNone(_FakeTool.received["shared_secret"])


class _FakeRestForwarder(BaseHTTPRequestHandler):
    received = None
    status = 200
    response = {"status": 200, "headers": {"content-type": "text/plain"}, "body": "ok"}

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        type(self).received = {
            "path": self.path,
            "body": body,
            "shared_secret": self.headers.get("X-Toolstack-Secret"),
        }
        payload = json.dumps(type(self).response).encode("utf-8")
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class RestForward(unittest.TestCase):
    def setUp(self):
        _FakeRestForwarder.received = None
        _FakeRestForwarder.status = 200
        _FakeRestForwarder.response = {"status": 200, "headers": {"content-type": "text/plain"}, "body": "ok"}
        self.server = HTTPServer(("127.0.0.1", 0), _FakeRestForwarder)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def _op(self):
        return ToolOp("jira", "get_user", "read", self.port, "rest",
                      "GET", "/users/{user_id}", "api.example.test", "none")

    def test_posts_sendrequest_with_context_and_configured_secret(self):
        rt = HttpRuntime(tool_secret=lambda tool_id: "chan" if tool_id == "jira" else None)
        result = rt.execute(self._op(), {"variables": {"user_id": "u42"}}, 7, "hermes")
        self.assertEqual(result, {"status": 200, "headers": {"content-type": "text/plain"}, "body": "ok"})
        self.assertEqual(_FakeRestForwarder.received["path"], "/sendrequest")
        self.assertEqual(_FakeRestForwarder.received["shared_secret"], "chan")
        sent = _FakeRestForwarder.received["body"]
        self.assertEqual(sent["op"], "get_user")
        self.assertEqual(sent["arguments"], {"variables": {"user_id": "u42"}})
        self.assertEqual(sent["broker_request_id"], 7)
        self.assertEqual(sent["caller"], {"name": "hermes"})

    def test_missing_shared_secret_dispatches_without_header(self):
        rt = HttpRuntime(tool_secret=lambda tool_id: None)
        rt.execute(self._op(), {}, 1, "hermes")
        self.assertEqual(_FakeRestForwarder.received["path"], "/sendrequest")
        self.assertIsNone(_FakeRestForwarder.received["shared_secret"])

    def test_outbound_unreachable_error_maps_to_tool_unreachable(self):
        _FakeRestForwarder.status = 502
        _FakeRestForwarder.response = {"error": "outbound_unreachable", "reason": "timed out"}
        rt = HttpRuntime(tool_secret=lambda tool_id: "chan")
        with self.assertRaises(RuntimeError) as cm:
            rt.execute(self._op(), {}, 1, "hermes")
        self.assertIn("outbound unreachable", str(cm.exception))

    def test_forwarder_error_maps_to_tool_failure(self):
        _FakeRestForwarder.status = 400
        _FakeRestForwarder.response = {"error": "missing_variable", "name": "user_id"}
        rt = HttpRuntime(tool_secret=lambda tool_id: "chan")
        with self.assertRaises(RuntimeError) as cm:
            rt.execute(self._op(), {}, 1, "hermes")
        self.assertIn("missing_variable", str(cm.exception))


class _FakeMcpTool(BaseHTTPRequestHandler):
    """A minimal streamable-HTTP MCP server for exercising the broker's MCP client.
    Class attributes configure the response shape; ``received`` records every request."""

    received: list = []
    mode = "json"            # "json" | "sse"
    tool_result = None       # structuredContent for tools/call (None -> echo the arguments)
    force_error = None       # if set, tools/call replies with this JSON-RPC error object
    is_error = False         # value of result.isError on a tools/call reply
    bad_init = False         # if set, initialize replies with a null (non-dict) result

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        msg = json.loads(self.rfile.read(length)) if length else {}
        type(self).received.append({
            "method": msg.get("method"),
            "message": msg,
            "session": self.headers.get("Mcp-Session-Id"),
            "secret": self.headers.get("X-Toolstack-Secret"),
            "protocol": self.headers.get("MCP-Protocol-Version"),
        })
        msg_id = msg.get("id")
        if msg_id is None:  # a notification (notifications/initialized) -> 202, no body
            self.send_response(202)
            self.end_headers()
            return
        method = msg.get("method")
        if method == "initialize":
            result = None if type(self).bad_init else {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1"},
            }
            self._reply(msg_id, result=result, session="sess-xyz")
        elif method == "tools/call":
            if type(self).force_error is not None:
                self._reply(msg_id, error=type(self).force_error)
                return
            structured = (type(self).tool_result if type(self).tool_result is not None
                          else {"echoed": (msg.get("params") or {}).get("arguments")})
            self._reply(msg_id, result={
                "content": [{"type": "text", "text": json.dumps(structured)}],
                "structuredContent": structured,
                "isError": type(self).is_error,
            })
        else:
            self._reply(msg_id, error={"code": -32601, "message": "method not found"})

    def _reply(self, msg_id, result=None, error=None, session=None):
        env = {"jsonrpc": "2.0", "id": msg_id}
        if error is not None:
            env["error"] = error
        else:
            env["result"] = result
        if type(self).mode == "sse":
            payload = ("event: message\ndata: " + json.dumps(env) + "\n\n").encode("utf-8")
            ctype = "text/event-stream"
        else:
            payload = json.dumps(env).encode("utf-8")
            ctype = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class McpForward(unittest.TestCase):
    """The broker as a streamable-HTTP MCP client: a type='mcp' ToolOp drives
    initialize -> initialized -> tools/call, and the MCP result comes back."""

    def setUp(self):
        _FakeMcpTool.received = []
        _FakeMcpTool.mode = "json"
        _FakeMcpTool.tool_result = None
        _FakeMcpTool.force_error = None
        _FakeMcpTool.is_error = False
        _FakeMcpTool.bad_init = False
        self.server = HTTPServer(("127.0.0.1", 0), _FakeMcpTool)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def _op(self, op="say"):
        return ToolOp("echo-mcp", op, "read", self.port, "mcp")

    def test_runs_handshake_then_calls_tool_with_op_as_name(self):
        result = HttpRuntime().execute(self._op("say"), {"m": "hi"}, 7, "hermes")
        methods = [r["method"] for r in _FakeMcpTool.received]
        self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/call"])
        call = _FakeMcpTool.received[-1]["message"]
        self.assertEqual(call["params"]["name"], "say")       # op IS the MCP tool name
        self.assertEqual(call["params"]["arguments"], {"m": "hi"})
        self.assertEqual(result["structuredContent"], {"echoed": {"m": "hi"}})
        self.assertFalse(result["isError"])

    def test_passes_broker_context_in_meta(self):
        HttpRuntime().execute(self._op("whoami"), {}, 99, "hermes")
        meta = _FakeMcpTool.received[-1]["message"]["params"]["_meta"]
        self.assertEqual(meta["broker_request_id"], 99)
        self.assertEqual(meta["caller"], {"name": "hermes"})

    def test_captures_and_resends_session_id(self):
        HttpRuntime().execute(self._op(), {}, 1, "hermes")
        sessions = [r["session"] for r in _FakeMcpTool.received]
        # initialize carries none; the server pins "sess-xyz", resent on later requests
        self.assertEqual(sessions, [None, "sess-xyz", "sess-xyz"])

    def test_sends_negotiated_protocol_version_after_initialize(self):
        HttpRuntime().execute(self._op(), {}, 1, "hermes")
        protocols = [r["protocol"] for r in _FakeMcpTool.received]
        # initialize carries no version header (not negotiated yet); the streamable-HTTP
        # transport requires it on every later request, set to the server's negotiated value
        self.assertEqual(protocols, [None, "2025-06-18", "2025-06-18"])

    def test_non_dict_initialize_result_raises(self):
        _FakeMcpTool.bad_init = True
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(self._op(), {}, 1, "hermes")

    def test_sends_shared_secret_on_every_request(self):
        rt = HttpRuntime(tool_secret=lambda t: "sekret" if t == "echo-mcp" else None)
        rt.execute(self._op(), {}, 1, "hermes")
        self.assertEqual([r["secret"] for r in _FakeMcpTool.received],
                         ["sekret", "sekret", "sekret"])

    def test_parses_sse_response(self):
        _FakeMcpTool.mode = "sse"
        result = HttpRuntime().execute(self._op("say"), {"m": "yo"}, 1, "hermes")
        self.assertEqual(result["structuredContent"], {"echoed": {"m": "yo"}})

    def test_jsonrpc_error_raises(self):
        _FakeMcpTool.force_error = {"code": -32602, "message": "unknown tool"}
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(self._op("nope"), {}, 1, "hermes")

    def test_tool_level_iserror_passes_through_without_raising(self):
        # isError is the tool's handled-error channel (like an api tool's 200 + error
        # body): it must reach the caller, not surface as a 502.
        _FakeMcpTool.is_error = True
        _FakeMcpTool.tool_result = {"message": "could not do it"}
        result = HttpRuntime().execute(self._op("say"), {}, 1, "hermes")
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"], {"message": "could not do it"})

    def test_unreachable_tool_raises(self):
        with self.assertRaises(RuntimeError):
            HttpRuntime(timeout=2).execute(ToolOp("echo-mcp", "say", "read", 1, "mcp"),
                                           {}, 1, "hermes")


class EnvToolSecret(unittest.TestCase):
    """_env_tool_secret: the default resolver, sourced from the toolyard state file.

    The legacy TOOLSTACK_TOOL_SECRET_<TOOL> env var path was retired in Phase 5;
    these tests pin the new state-file-only contract so a future change can't
    re-introduce the silent override that produced channel_secret_mismatch when
    the env var happened to be set on a fresh install.
    """

    def test_reads_from_state_file(self):
        fake = mock.Mock(e_secret_for=mock.Mock(return_value="sekret"))
        with mock.patch("broker.tool_state.ToolState", return_value=fake):
            self.assertEqual(_env_tool_secret("echo"), "sekret")
            fake.e_secret_for.assert_called_once_with("echo")

    def test_missing_tool_returns_none(self):
        fake = mock.Mock(e_secret_for=mock.Mock(return_value=None))
        with mock.patch("broker.tool_state.ToolState", return_value=fake):
            self.assertIsNone(_env_tool_secret("absent"))

    def test_empty_value_is_none(self):
        fake = mock.Mock(e_secret_for=mock.Mock(return_value=""))
        with mock.patch("broker.tool_state.ToolState", return_value=fake):
            self.assertIsNone(_env_tool_secret("ghost"))

    def test_strips_surrounding_whitespace(self):
        # the tool reads its copy through .strip(); the broker must match or every call 401s
        fake = mock.Mock(e_secret_for=mock.Mock(return_value="  abc\n"))
        with mock.patch("broker.tool_state.ToolState", return_value=fake):
            self.assertEqual(_env_tool_secret("echo"), "abc")

    def test_legacy_env_var_is_ignored(self):
        # The retired TOOLSTACK_TOOL_SECRET_<TOOL> env var must NOT shadow the
        # state file. Pin this so a future change can't re-introduce the bug
        # (a stray /etc/toolstack/admin.env value producing channel_secret_mismatch).
        fake = mock.Mock(e_secret_for=mock.Mock(return_value="from_state_file"))
        with mock.patch.dict(os.environ, {"TOOLSTACK_TOOL_SECRET_ECHO": "from_env"}):
            with mock.patch("broker.tool_state.ToolState", return_value=fake):
                self.assertEqual(_env_tool_secret("echo"), "from_state_file")


if __name__ == "__main__":
    unittest.main()
