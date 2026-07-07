import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from toolstack_forwarder.config import load_config
from toolstack_forwarder.server import serve


class _Upstream(BaseHTTPRequestHandler):
    server_version = "upstream"
    sys_version = ""

    def do_GET(self):
        self.server.seen.append({"method": "GET", "path": self.path, "headers": dict(self.headers), "body": b""})
        if self.path == "/v1/redirect":
            self.send_response(302)
            self.send_header("Location", "/v1/elsewhere")
            self.end_headers()
            return
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "sid=secret")
        self.send_header("Connection", "close")
        self.send_header("X-Rate", "9")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.seen.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"abcdef")

    def log_message(self, *args):
        pass


class ForwarderServer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = Path(self.tmp)
        self.secrets = self.root / "secrets"
        self.secrets.mkdir()
        (self.secrets / "broker_secret").write_text("chan\n")
        self.upstream = HTTPServer(("127.0.0.1", 0), _Upstream)
        self.upstream.seen = []
        self._start(self.upstream)
        self.addCleanup(self.upstream.server_close)

    def _start(self, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return thread

    def _config(self, extra_ops: str = ""):
        port = self.upstream.server_address[1]
        toml = self.root / "toolyard.toml"
        toml.write_text(f"""\
id = "rest_demo"
type = "rest"
base_url = "http://127.0.0.1:{port}/v1"

[entrypoint]
port = 4600

[[operations]]
name = "get_item"
risk = "read"
verb = "GET"
path = "/items/{{item_id}}"
allowed_headers = ["X-Trace"]

{extra_ops}
""")
        return load_config(toml)

    def _forwarder(self, cfg=None, max_body=1024):
        server = serve("127.0.0.1", 0, cfg or self._config(), self.secrets, timeout=2, max_body=max_body)
        self._start(server)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _post(self, url, payload, secret="chan"):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url + "/sendrequest",
            data=body,
            headers={"Content-Type": "application/json", "X-Toolstack-Secret": secret},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def test_forwards_and_returns_sanitized_response_envelope(self):
        status, body = self._post(
            self._forwarder(),
            {"op": "get_item", "arguments": {"variables": {"item_id": "i1"}, "headers": {"X-Trace": "abc"}}},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], 201)
        self.assertEqual(body["body"], '{"ok":true}')
        self.assertEqual(body["headers"]["x-rate"], "9")
        self.assertNotIn("set-cookie", body["headers"])
        self.assertNotIn("connection", body["headers"])
        self.assertEqual(self.upstream.seen[-1]["path"], "/v1/items/i1")
        self.assertEqual(self.upstream.seen[-1]["headers"]["X-Trace"], "abc")

    def test_broker_secret_mismatch_is_401_json_when_configured(self):
        status, body = self._post(self._forwarder(), {"op": "get_item", "arguments": {}}, secret="wrong")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "channel_secret_mismatch")

    def test_missing_broker_secret_file_disables_channel_auth(self):
        (self.secrets / "broker_secret").unlink()
        status, body = self._post(self._forwarder(), {"op": "get_item", "arguments": {"variables": {"item_id": "i1"}}}, secret="anything")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], 201)

    def test_does_not_follow_upstream_redirect(self):
        cfg = self._config("""
[[operations]]
name = "redirect"
risk = "read"
verb = "GET"
path = "/redirect"
""")
        status, body = self._post(self._forwarder(cfg), {"op": "redirect", "arguments": {}})
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], 302)
        self.assertEqual(body["headers"]["location"], "/v1/elsewhere")

    def test_response_cap_returns_error_envelope(self):
        cfg = self._config("""
[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
body_kind = "text"
""")
        status, body = self._post(self._forwarder(cfg, max_body=4), {"op": "login", "arguments": {"body": "{}"}})
        self.assertEqual(status, 502)
        self.assertEqual(body["error"], "response_too_large")
        self.assertEqual(body["limit_bytes"], 4)

    def test_matching_secret_update_rule_writes_via_proxy(self):
        cfg = self._config("""
[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
body_kind = "text"
secret_update_rules = [
  { secret_name = "auth_token", response_type = "plaintext", extract_path = "abc(def)", match_status = "200" },
]

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
writable = true
""")
        writes = []

        def fake_write(name, value):
            writes.append((name, value))
            return 200, {"ok": True}

        with unittest.mock.patch("toolstack_forwarder.rules.write_secret_via_proxy", fake_write):
            status, body = self._post(self._forwarder(cfg), {"op": "login", "arguments": {"body": "{}"}})
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], 200)
        self.assertEqual(writes, [("auth_token", "def")])

    def test_rule_extraction_failure_writes_nothing_and_returns_error(self):
        cfg = self._config("""
[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
body_kind = "text"
secret_update_rules = [
  { secret_name = "auth_token", response_type = "plaintext", extract_path = "nope=([a-z]+)", match_status = "200" },
]

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
writable = true
""")
        with unittest.mock.patch("toolstack_forwarder.rules.write_secret_via_proxy") as write:
            status, body = self._post(self._forwarder(cfg), {"op": "login", "arguments": {"body": "{}"}})
        self.assertEqual(status, 502)
        self.assertEqual(body["error"], "rule_extraction_failed")
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
