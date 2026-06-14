"""HttpRuntime: forwards to 127.0.0.1:<port>/v1/actions/<op> with broker context,
returns the tool's JSON, and raises (-> 502) when the tool is unreachable."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from broker.registry import ToolOp
from broker.runtime import HttpRuntime


class _FakeTool(BaseHTTPRequestHandler):
    received = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        type(self).received = {"path": self.path, "body": body}
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
        tool_op = ToolOp("echo", "say", "low", self.port, "rest")
        result = HttpRuntime().execute(tool_op, {"m": "hi"}, 7, "hermes")

        self.assertEqual(_FakeTool.received["path"], "/v1/actions/say")
        sent = _FakeTool.received["body"]
        self.assertEqual(sent["arguments"], {"m": "hi"})
        self.assertEqual(sent["broker_request_id"], 7)
        self.assertEqual(sent["caller"], {"name": "hermes"})
        self.assertTrue(result["ok"])

    def test_unreachable_tool_raises(self):
        tool_op = ToolOp("echo", "say", "low", 1, "rest")  # nothing listening on :1
        with self.assertRaises(RuntimeError):
            HttpRuntime(timeout=2).execute(tool_op, {}, 1, "hermes")


if __name__ == "__main__":
    unittest.main()
