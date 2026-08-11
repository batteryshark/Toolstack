import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from sps.tool_sdk import SecretClient

from toolstack_forwarder.config import load_config
from toolstack_forwarder.server import serve


class _Upstream(BaseHTTPRequestHandler):
    server_version = "upstream"
    sys_version = ""

    def do_GET(self):
        self.server.seen.append({"method": "GET", "path": self.path,
                                "headers": dict(self.headers), "body": b""})
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
        self.server.seen.append({"method": "POST", "path": self.path,
                                "headers": dict(self.headers), "body": body})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"abcdef")

    def log_message(self, *args):
        pass


def _fake_secrets(table: dict | None = None) -> SecretClient:
    """In-memory SecretClient stand-in for tests. The real client uses SPS;
    we mimic the get / writeback surface without touching the network."""
    table = dict(table or {"broker_secret": "chan"})
    store = {"_t": table}

    class _Fake:
        def cache_get(self, name):
            return table.get(name)
        def get(self, name):
            if name not in table:
                raise KeyError(name)
            return table[name]
        def writeback(self, name, value):
            table[name] = value
        def refresh_all(self):
            pass
        def refresh(self, name):
            if name not in table:
                raise KeyError(name)
            return table[name]

    fake = _Fake()
    fake.table = store
    return fake


class ForwarderServer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = Path(self.tmp)
        self.upstream = HTTPServer(("127.0.0.1", 0), _Upstream)
        self.upstream.seen = []
        self._start(self.upstream)
        self.addCleanup(self.upstream.server_close)
        # Default channel secret; tests can override via TOOLSTACK_E_SECRET.
        self._prev_env = os.environ.get("TOOLSTACK_E_SECRET")
        os.environ["TOOLSTACK_E_SECRET"] = "chan"
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._prev_env is None:
            os.environ.pop("TOOLSTACK_E_SECRET", None)
        else:
            os.environ["TOOLSTACK_E_SECRET"] = self._prev_env

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

    def _forwarder(self, cfg=None, max_body=1024, secrets=None):
        cfg = cfg or self._config()
        secrets = secrets if secrets is not None else _fake_secrets()
        server = serve("127.0.0.1", 0, cfg, secrets, timeout=2, max_body=max_body)
        self._start(server)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _post(self, url, payload, secret="chan"):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if secret is not None:
            headers["X-Toolstack-Secret"] = secret
        req = urllib.request.Request(
            url + "/sendrequest",
            data=body,
            headers=headers,
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
            {"op": "get_item",
             "arguments": {"variables": {"item_id": "i1"},
                           "headers": {"X-Trace": "abc"}}},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], 201)
        self.assertEqual(body["body"], '{"ok":true}')
        self.assertEqual(body["headers"]["x-rate"], "9")
        self.assertNotIn("set-cookie", body["headers"])
        self.assertNotIn("connection", body["headers"])
        self.assertEqual(self.upstream.seen[-1]["path"], "/v1/items/i1")
        self.assertEqual(self.upstream.seen[-1]["headers"]["X-Trace"], "abc")

    def test_logs_substituted_url_without_headers_or_body(self):
        with mock.patch("sys.stdout") as fake_stdout:
            status, _ = self._post(
                self._forwarder(),
                {"op": "get_item",
                 "arguments": {"variables": {"item_id": "i1"},
                               "headers": {"X-Trace": "abc"}}},
            )
        self.assertEqual(status, 200)
        logged = "".join(call.args[0] for call in fake_stdout.write.call_args_list
                         if call.args and isinstance(call.args[0], str))
        self.assertIn("http://127.0.0.1:", logged)
        self.assertIn("/v1/items/i1", logged)
        self.assertNotIn("X-Trace", logged)
        self.assertNotIn("abc", logged)

    def test_broker_secret_mismatch_is_401_json_when_configured(self):
        status, body = self._post(self._forwarder(), {"op": "get_item", "arguments": {}}, secret="wrong")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "channel_secret_mismatch")

    def test_missing_e_secret_env_disables_channel_auth(self):
        # No TOOLSTACK_E_SECRET -> channel auth off; any header value passes.
        os.environ.pop("TOOLSTACK_E_SECRET")
        status, body = self._post(
            self._forwarder(),
            {"op": "get_item", "arguments": {"variables": {"item_id": "i1"}}},
            secret="anything",
        )
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
allowed_headers = []
""")
        url = self._forwarder(cfg, max_body=16)
        long_body = "abcdefghijklmnop" * 8   # > 16
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(
                urllib.request.Request(
                    url + "/sendrequest",
                    data=json.dumps(
                        {"op": "login",
                         "arguments": {"body": long_body, "headers": {}}}
                    ).encode(),
                    headers={"Content-Type": "application/json",
                              "X-Toolstack-Secret": "chan"},
                    method="POST",
                ),
                timeout=5,
            )
        # `body_too_large` is a RequestBuildError, mapped to HTTP 400 by
        # server.py; the original test expected 502 because that is the
        # status shape for upstream failures, but the surface here is
        # *request* validation, not upstream failure.
        self.assertEqual(cm.exception.code, 400)
        resp_body = json.loads(cm.exception.read())
        self.assertEqual(resp_body["error"], "body_too_large")

    def test_secret_update_rule_writes_through_SDK(self):
        """Phase 5: secret_update_rules now call SPS via the SDK rather than
        a host-side write-proxy socket. Verify the extracted value lands in
        the SPS-backed SecretClient cache."""
        cfg = self._config("""
[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
allowed_headers = []
body_kind = "text"
body_content_type = "application/json"
secret_update_rules = [
  { secret_name = "auth_token", response_type = "plaintext", extract_path = "abc(def)", match_status = "200" },
]

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
writable = true
""")
        secrets = _fake_secrets({"auth_token": "old"})
        url = self._forwarder(cfg, secrets=secrets)
        status, body = self._post(url, {"op": "login", "arguments": {"body": "{}"}})
        self.assertEqual(status, 200)
        # writeback saw the real body (not the redacted caller's body)
        self.assertEqual(secrets.table["_t"]["auth_token"], "def")

    def test_secret_update_rule_failure_partial_skips_remaining_writes(self):
        # Two rules; the FIRST succeeds, the SECOND's extract regex fails.
        # Extraction is all-or-nothing: when ANY rule's extract fails, we
        # raise RuleError("rule_extraction_failed") before any write, so
        # auth_token is NOT updated.
        cfg = self._config("""
[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
allowed_headers = []
body_kind = "text"
body_content_type = "application/json"
secret_update_rules = [
  { secret_name = "auth_token",  response_type = "plaintext", extract_path = "abc(def)", match_status = "200" },
  { secret_name = "refresh_token", response_type = "plaintext", extract_path = "nope=([a-z]+)", match_status = "200" },
]

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
writable = true

[[secrets]]
name = "refresh_token"
field = "REFRESH_TOKEN"
writable = true
""")
        secrets = _fake_secrets({"auth_token": "old", "refresh_token": "old"})
        url = self._forwarder(cfg, secrets=secrets)
        status, body = self._post(url, {"op": "login", "arguments": {"body": "{}"}})
        self.assertEqual(status, 502)
        self.assertEqual(body["error"], "rule_extraction_failed")
        # All-or-nothing: nothing was written.
        self.assertEqual(secrets.table["_t"]["auth_token"], "old")
        self.assertEqual(secrets.table["_t"]["refresh_token"], "old")


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
