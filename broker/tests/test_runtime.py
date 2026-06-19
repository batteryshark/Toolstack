"""HttpRuntime: forwards to 127.0.0.1:<port>/v1/actions/<op> with broker context,
returns the tool's JSON, and raises (-> 502) when the tool is unreachable."""

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
