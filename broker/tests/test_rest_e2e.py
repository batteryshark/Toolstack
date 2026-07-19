"""REST end-to-end: broker runtime -> real forwarder -> real upstream.

This stays process-local and stdlib-only: a fake upstream http.server, the real
toolstack_forwarder server, broker HttpRuntime, and a fake Unix write-proxy for
secret update rules.
"""

import json
import os
import shutil
import socket
import socketserver
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from broker.registry import ToolOp
from broker.runtime import HttpRuntime, ToolUnreachable
from toolstack_forwarder.config import load_config
from toolstack_forwarder.server import serve


class _Upstream(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        type(self).seen.append((self.command, self.path, dict(self.headers), b""))
        if self.path.startswith("/items/"):
            self._send(200, {"id": self.path.rsplit("/", 1)[-1]})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen.append((self.command, self.path, dict(self.headers), body))
        if self.path == "/login":
            self._send(200, {"session": {"token": "rotated-token"}})
        else:
            self._send(404, {"error": "not_found"})

    def _send(self, status, obj):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _WriteProxy(socketserver.StreamRequestHandler):
    writes = []
    status = 200

    def handle(self):
        line = self.rfile.readline().decode("latin-1").strip()
        headers = {}
        while True:
            h = self.rfile.readline().decode("latin-1")
            if h in ("\r\n", "\n", ""):
                break
            k, _, v = h.partition(":")
            headers[k.lower()] = v.strip()
        body = self.rfile.read(int(headers.get("content-length", "0") or 0))
        type(self).writes.append((line, json.loads(body)))
        payload = json.dumps({"ok": type(self).status == 200}).encode()
        self.wfile.write(
            f"HTTP/1.1 {type(self).status} OK\r\nContent-Length: {len(payload)}\r\n"
            "Content-Type: application/json\r\nConnection: close\r\n\r\n".encode()
            + payload
        )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RestE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = Path(self.tmp)
        self.secrets = self.root / "secrets"
        self.secrets.mkdir()
        (self.secrets / "broker_secret").write_text("chan")

        _Upstream.seen = []
        self.upstream = HTTPServer(("127.0.0.1", 0), _Upstream)
        self._start(self.upstream)
        self.addCleanup(self.upstream.server_close)
        self.upstream_port = self.upstream.server_address[1]

    def _start(self, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return thread

    def _forwarder(self, base_url=None):
        port = _free_port()
        toml = self.root / "toolyard.toml"
        toml.write_text(f"""\
id = "rest_demo"
type = "rest"
base_url = "{base_url or f'http://127.0.0.1:{self.upstream_port}'}"

[entrypoint]
port = {port}
command = "python3 -m toolstack_forwarder"

[[operations]]
name = "get_item"
risk = "read"
verb = "GET"
path = "/items/{{item_id}}"
allowed_headers = ["X-Demo-Trace"]

[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
body_kind = "text"
secret_update_rules = [
  {{ secret_name = "auth_token", response_type = "json", extract_path = "session.token", match_status = "200" }},
]

[[secrets]]
name = "auth_token"
field = "REST_DEMO_AUTH_TOKEN"
writable = true
""")
        server = serve("127.0.0.1", port, load_config(toml), self.secrets, timeout=2, max_body=1024 * 1024)
        self._start(server)
        self.addCleanup(server.server_close)
        return port

    def _runtime(self):
        return HttpRuntime(timeout=3, tool_secret=lambda tool_id: "chan")

    def _op(self, port, name="get_item", verb="GET", path="/items/{item_id}", body_kind="none"):
        return ToolOp("rest_demo", name, "read", port, "rest", verb, path, "127.0.0.1", body_kind)

    def test_successful_get_reaches_upstream(self):
        port = self._forwarder()
        result = self._runtime().execute(
            self._op(port),
            {"variables": {"item_id": "i42"}, "headers": {"X-Demo-Trace": "abc"}},
            7,
            "hermes",
        )
        self.assertEqual(result["status"], 200)
        self.assertEqual(json.loads(result["body"]), {"id": "i42"})
        self.assertEqual(_Upstream.seen[-1][1], "/items/i42")
        self.assertEqual(_Upstream.seen[-1][2]["X-Demo-Trace"], "abc")

    def test_header_allowlist_rejection_surfaces_as_tool_failure(self):
        port = self._forwarder()
        with self.assertRaises(RuntimeError) as cm:
            self._runtime().execute(
                self._op(port),
                {"variables": {"item_id": "i42"}, "headers": {"Cookie": "sid=x"}},
                7,
                "hermes",
            )
        self.assertIn("header_not_allowed", str(cm.exception))

    @unittest.skip("Phase 5: writeback path is the SPS SDK now, not a host UNIX socket")
    def test_login_writeback_uses_write_proxy(self):
        _WriteProxy.writes = []
        proxy_sock = str(self.root / "secrets.sock")
        proxy = socketserver.UnixStreamServer(proxy_sock, _WriteProxy)
        self._start(proxy)
        self.addCleanup(proxy.server_close)
        port = self._forwarder()
        with mock.patch.dict(os.environ, {"TOOLYARD_SECRETS_SOCKET": proxy_sock}):
            result = self._runtime().execute(
                self._op(port, "login", "POST", "/login", "text"),
                {"body": "{}"},
                8,
                "hermes",
            )
        self.assertEqual(result["status"], 200)
        self.assertEqual(_WriteProxy.writes[0][0], "POST /v1/secrets/auth_token HTTP/1.1")
        self.assertEqual(_WriteProxy.writes[0][1]["value"], "rotated-token")

    def test_upstream_unreachable_maps_to_tool_unreachable(self):
        port = self._forwarder(base_url="http://127.0.0.1:1")
        with self.assertRaises(ToolUnreachable):
            self._runtime().execute(self._op(port), {"variables": {"item_id": "i42"}}, 7, "hermes")


if __name__ == "__main__":
    unittest.main()
