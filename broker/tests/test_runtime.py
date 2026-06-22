"""HttpRuntime: forwards to 127.0.0.1:<port>/v1/actions/<op> with broker context,
returns the tool's JSON, and raises (-> 502) when the tool is unreachable."""

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from broker.registry import ToolOp
from broker.runtime import HttpRuntime, RestTemplateError, _env_tool_secret, resolve_rest_path


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
        # initialize carries none; the server pins "sess-xyz", resent on the rest
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


class _FakeRestTool(BaseHTTPRequestHandler):
    """A plain HTTP service for exercising the rest passthrough. Records the last request;
    class attributes set the response status/body."""

    received: dict = {}
    status = 200
    resp_body = None         # None -> {"ok": True}
    resp_ctype = "application/json"
    resp_location = None      # if set, sent as a Location header (to test redirect handling)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = None
        type(self).received = {
            "method": self.command,
            "path": self.path,
            "body": body,
            "request_id": self.headers.get("X-Toolstack-Request-Id"),
            "caller": self.headers.get("X-Toolstack-Caller"),
            "secret": self.headers.get("X-Toolstack-Secret"),
            "headers": {k.lower(): v for k, v in self.headers.items()},  # all received, lc names
        }
        obj = type(self).resp_body if type(self).resp_body is not None else {"ok": True}
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(type(self).status)
        self.send_header("Content-Type", type(self).resp_ctype)
        self.send_header("Content-Length", str(len(payload)))
        if type(self).resp_location:
            self.send_header("Location", type(self).resp_location)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    def log_message(self, *args):
        pass


class RestForward(unittest.TestCase):
    """The broker as a verb-as-op passthrough: a type='rest' ToolOp forwards
    <verb> <path> + body + caller headers to the tool and returns its {status, headers, body}."""

    def setUp(self):
        _FakeRestTool.received = {}
        _FakeRestTool.status = 200
        _FakeRestTool.resp_body = None
        _FakeRestTool.resp_ctype = "application/json"
        _FakeRestTool.resp_location = None
        self.server = HTTPServer(("127.0.0.1", 0), _FakeRestTool)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def _op(self, verb="GET"):
        return ToolOp("kv", verb, "read", self.port, "rest")

    def test_forwards_verb_path_body_and_returns_status_body(self):
        result = HttpRuntime().execute(
            self._op("POST"), {"path": "/items", "body": {"key": "a", "value": 1}}, 7, "hermes")
        self.assertEqual(_FakeRestTool.received["method"], "POST")  # op IS the verb
        self.assertEqual(_FakeRestTool.received["path"], "/items")
        self.assertEqual(_FakeRestTool.received["body"], {"key": "a", "value": 1})
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], {"ok": True})

    def test_sends_broker_context_in_headers(self):
        HttpRuntime().execute(self._op("GET"), {"path": "/items"}, 99, "hermes")
        self.assertEqual(_FakeRestTool.received["request_id"], "99")
        self.assertEqual(_FakeRestTool.received["caller"], "hermes")

    def test_4xx_passes_through_without_raising(self):
        # a 404 for a missing resource is a legitimate REST answer, not a broker error
        _FakeRestTool.status = 404
        _FakeRestTool.resp_body = {"error": "not_found"}
        result = HttpRuntime().execute(self._op("GET"), {"path": "/items/nope"}, 1, "hermes")
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["body"], {"error": "not_found"})

    def test_query_dict_is_appended(self):
        HttpRuntime().execute(self._op("GET"), {"path": "/items", "query": {"limit": "5"}}, 1, "hermes")
        self.assertIn("limit=5", _FakeRestTool.received["path"])

    def test_sends_shared_secret_when_configured(self):
        rt = HttpRuntime(tool_secret=lambda t: "sek" if t == "kv" else None)
        rt.execute(self._op("GET"), {"path": "/items"}, 1, "hermes")
        self.assertEqual(_FakeRestTool.received["secret"], "sek")

    def test_missing_path_raises(self):
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(self._op("GET"), {}, 1, "hermes")

    def test_path_must_start_with_a_single_slash(self):
        # "@evil/x" -> http://127.0.0.1:port@evil/x would smuggle a host into the authority
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(self._op("GET"), {"path": "@evil/x"}, 1, "hermes")
        # "//evil/x" -> protocol-relative host
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(self._op("GET"), {"path": "//evil/x"}, 1, "hermes")

    def test_non_printable_ascii_in_path_raises(self):
        # CRLF (smuggling), NUL, space, and raw non-ASCII all rejected with one clean error
        for bad in ["/x\r\nHost: evil", "/x\x00y", "/a b", "/café"]:
            with self.assertRaises(RuntimeError):
                HttpRuntime().execute(self._op("GET"), {"path": bad}, 1, "hermes")

    def test_non_verb_op_raises(self):
        # method-injection guard: the registry only registers declared verb ops, but never
        # use an arbitrary op string as an HTTP method
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(ToolOp("kv", "FROBNICATE", "read", self.port, "rest"),
                                  {"path": "/x"}, 1, "hermes")

    def test_does_not_follow_tool_redirects(self):
        # a tool-issued 3xx must NOT be auto-followed (SSRF guard); it returns as data, and
        # the broker never re-requests the Location target.
        _FakeRestTool.status = 302
        _FakeRestTool.resp_location = "/elsewhere"
        result = HttpRuntime().execute(self._op("GET"), {"path": "/items"}, 1, "hermes")
        self.assertEqual(result["status"], 302)
        self.assertEqual(_FakeRestTool.received["path"], "/items")  # not "/elsewhere"

    def test_unreachable_tool_raises(self):
        with self.assertRaises(RuntimeError):
            HttpRuntime(timeout=2).execute(ToolOp("kv", "GET", "read", 1, "rest"),
                                           {"path": "/x"}, 1, "hermes")

    def test_forwards_caller_headers(self):
        HttpRuntime().execute(
            self._op("GET"),
            {"path": "/items", "headers": {"Accept": "application/xml", "X-Custom": "v"}}, 1, "hermes")
        got = _FakeRestTool.received["headers"]
        self.assertEqual(got["accept"], "application/xml")
        self.assertEqual(got["x-custom"], "v")

    def test_reserved_request_headers_cannot_be_spoofed(self):
        HttpRuntime().execute(
            self._op("GET"),
            {"path": "/items", "headers": {"X-Toolstack-Caller": "evil", "Host": "evil.example",
                                           "Content-Length": "999"}}, 5, "hermes")
        got = _FakeRestTool.received["headers"]
        self.assertEqual(got["x-toolstack-caller"], "hermes")  # broker's identity wins, not "evil"
        self.assertNotIn("evil", got.get("host", ""))          # Host stays on the loopback target

    def test_invalid_header_name_raises(self):
        with self.assertRaises(RuntimeError):
            HttpRuntime().execute(self._op("GET"), {"path": "/x", "headers": {"Bad Name": "v"}}, 1, "hermes")

    def test_invalid_header_value_raises(self):
        # CRLF injection, non-ASCII (http.client can't latin-1 it), and a non-string value
        for bad in ["a\r\nEvil: 1", "sn☃wman", {"x": 1}]:
            with self.assertRaises(RuntimeError):
                HttpRuntime().execute(self._op("GET"), {"path": "/x", "headers": {"X-H": bad}}, 1, "hermes")

    def test_trailing_newline_header_name_raises(self):
        with self.assertRaises(RuntimeError):  # \Z anchor, not $; a terminal \n must not pass
            HttpRuntime().execute(self._op("GET"), {"path": "/x", "headers": {"X-Inject\n": "v"}}, 1, "hermes")

    def test_returns_response_headers(self):
        _FakeRestTool.status = 201
        _FakeRestTool.resp_location = "/items/new"
        result = HttpRuntime().execute(self._op("POST"), {"path": "/items", "body": {"k": 1}}, 1, "hermes")
        self.assertEqual(result["status"], 201)
        self.assertEqual(result["headers"].get("Location"), "/items/new")    # full-fidelity passthrough
        self.assertEqual(result["headers"].get("Content-Type"), "application/json")


class ResolveTemplate(unittest.TestCase):
    """resolve_rest_path: fills a named rest op's path template from caller params, encoding each
    param to its segment and refusing any value that would escape it. Pure function, no I/O."""

    def test_single_segment_is_filled_and_encoded(self):
        self.assertEqual(
            resolve_rest_path("/me/todo/lists/{list_id}/tasks/{task_id}",
                              {"list_id": "AA 1", "task_id": "b#2"}),
            "/me/todo/lists/AA%201/tasks/b%232")   # space + '#' percent-encoded within one segment

    def test_slash_in_single_segment_is_rejected(self):
        # a single {name} segment can't carry '/': it would add path structure (use {+name} instead)
        with self.assertRaises(RestTemplateError):
            resolve_rest_path("/items/{id}", {"id": "a/b"})

    def test_no_params_returns_template_verbatim(self):
        self.assertEqual(resolve_rest_path("/me/messages", {}), "/me/messages")

    def test_missing_param_raises(self):
        with self.assertRaises(RestTemplateError):
            resolve_rest_path("/items/{id}", {})

    def test_non_string_param_raises(self):
        with self.assertRaises(RestTemplateError):
            resolve_rest_path("/items/{id}", {"id": 42})

    def test_dot_segment_param_is_rejected(self):
        for bad in ("..", "."):
            with self.assertRaises(RestTemplateError):
                resolve_rest_path("/items/{id}", {"id": bad})

    def test_reserved_tail_spans_segments(self):
        self.assertEqual(
            resolve_rest_path("/files/{+rest}", {"rest": "a/b/c.txt"}),
            "/files/a/b/c.txt")            # {+name} keeps '/'; an op opts into a subtree explicitly

    def test_reserved_tail_rejects_traversal_and_absolute(self):
        for bad in ("a/../b", "/etc/passwd", "a//b", "a/./b"):
            with self.assertRaises(RestTemplateError):
                resolve_rest_path("/files/{+rest}", {"rest": bad})

    def test_crlf_param_stays_encoded(self):
        # a CRLF in a value is percent-encoded, so no raw control char reaches the forwarded request
        out = resolve_rest_path("/items/{id}", {"id": "a\r\nb"})
        self.assertEqual(out, "/items/a%0D%0Ab")
        self.assertNotIn("\r", out)
        self.assertNotIn("\n", out)


class NamedRestForward(unittest.TestCase):
    """A named rest op: the broker fills the template from the caller's params and forwards the
    resolved <verb> <path> to the tool. The caller never supplies a free path."""

    def setUp(self):
        _FakeRestTool.received = {}
        _FakeRestTool.status = 200
        _FakeRestTool.resp_body = None
        _FakeRestTool.resp_ctype = "application/json"
        _FakeRestTool.resp_location = None
        self.server = HTTPServer(("127.0.0.1", 0), _FakeRestTool)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.server.shutdown)

    def _op(self, verb, template, op="get_task"):
        return ToolOp("graph", op, "read", self.port, "rest", verb=verb, path_template=template)

    def test_forwards_resolved_path_with_op_verb(self):
        result = HttpRuntime().execute(
            self._op("GET", "/me/todo/lists/{list_id}/tasks/{task_id}"),
            {"list_id": "42", "task_id": "99"}, 7, "hermes")
        self.assertEqual(_FakeRestTool.received["method"], "GET")          # verb from op.verb, not the name
        self.assertEqual(_FakeRestTool.received["path"], "/me/todo/lists/42/tasks/99")
        self.assertEqual(result["status"], 200)

    def test_query_is_appended_to_resolved_path(self):
        HttpRuntime().execute(self._op("GET", "/me/messages"),
                              {"query": {"$top": "5"}}, 7, "hermes")
        self.assertEqual(_FakeRestTool.received["path"], "/me/messages?%24top=5")

    def test_param_cannot_escape_its_segment(self):
        # a caller trying to traverse out of the route is refused before any forward
        with self.assertRaises(RestTemplateError):
            HttpRuntime().execute(self._op("GET", "/me/todo/lists/{list_id}"),
                                  {"list_id": "../../admin"}, 7, "hermes")
        self.assertEqual(_FakeRestTool.received, {})   # never reached the tool

    def test_body_is_forwarded_for_a_named_write(self):
        HttpRuntime().execute(self._op("POST", "/me/sendMail", op="send_mail"),
                              {"body": {"message": {"subject": "hi"}}}, 7, "hermes")
        self.assertEqual(_FakeRestTool.received["method"], "POST")
        self.assertEqual(_FakeRestTool.received["path"], "/me/sendMail")
        self.assertEqual(_FakeRestTool.received["body"], {"message": {"subject": "hi"}})


class EnvToolSecret(unittest.TestCase):
    """_env_tool_secret: the default resolver mapping a tool id to its env var."""

    def test_reads_per_tool_env_var(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_TOOL_SECRET_ECHO": "abc"}):
            self.assertEqual(_env_tool_secret("echo"), "abc")

    def test_collapses_non_alphanumerics_in_tool_id(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_TOOL_SECRET_APPLE_CALENDAR": "xyz"}):
            self.assertEqual(_env_tool_secret("apple-calendar"), "xyz")

    def test_unset_is_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(_env_tool_secret("absent"))

    def test_empty_value_is_none(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_TOOL_SECRET_GHOST": ""}):
            self.assertIsNone(_env_tool_secret("ghost"))

    def test_strips_surrounding_whitespace(self):
        # the tool reads its copy through .strip(); the broker must match or every call 401s
        with mock.patch.dict(os.environ, {"TOOLSTACK_TOOL_SECRET_ECHO": "  abc\n"}):
            self.assertEqual(_env_tool_secret("echo"), "abc")

    def test_whitespace_only_is_none(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_TOOL_SECRET_GHOST": "   "}):
            self.assertIsNone(_env_tool_secret("ghost"))


if __name__ == "__main__":
    unittest.main()
