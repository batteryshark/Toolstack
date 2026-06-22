"""toolyard.http_proxy: the generic REST proxy tool.

Covers the security spine as pure functions (base_url pinning, secret injection) plus one
end-to-end run through a real proxy server against a fake upstream: the injected auth goes
out, the caller's own headers do NOT, an unprovisioned secret fails closed, and a path that
tries to escape the base_url is refused.
"""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from toolyard import http_proxy


class BuildUpstream(unittest.TestCase):
    def test_joins_under_base_prefix(self):
        self.assertEqual(
            http_proxy.build_upstream("https://api.example.com/v1.0", "/me/messages", ""),
            "https://api.example.com/v1.0/me/messages")

    def test_no_prefix(self):
        self.assertEqual(
            http_proxy.build_upstream("https://api.example.com", "/me", "a=1"),
            "https://api.example.com/me?a=1")

    def test_dotdot_escaping_the_prefix_is_rejected(self):
        with self.assertRaises(ValueError):
            http_proxy.build_upstream("https://api.example.com/v1.0", "/../../admin", "")

    def test_dotdot_within_prefix_is_fine(self):
        # /v1.0/users/../me normalises to /v1.0/me, still under the prefix
        self.assertEqual(
            http_proxy.build_upstream("https://api.example.com/v1.0", "/users/../me", ""),
            "https://api.example.com/v1.0/me")

    def test_protocol_relative_path_rejected(self):
        with self.assertRaises(ValueError):
            http_proxy.build_upstream("https://api.example.com", "//evil.com/x", "")

    def test_percent_encoded_separators_rejected(self):
        # %2f/%2e survive normpath but an upstream that decodes them would escape the path scope.
        for p in ("/v1.0/users/..%2f..%2fadmin", "/v1.0/%2e%2e/admin", "/a%5cb"):
            with self.assertRaises(ValueError):
                http_proxy.build_upstream("https://api.example.com/v1.0", p, "")


class Injections(unittest.TestCase):
    def test_resolve_value_substitutes_secret(self):
        out = http_proxy.resolve_value("Bearer ${secret:tok}", read_secret=lambda n: "ABC")
        self.assertEqual(out, "Bearer ABC")

    def test_apply_injections_splits_by_target(self):
        h, q, b = http_proxy.apply_injections(
            [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:tok}"},
             {"into": "query", "name": "api-version", "value": "2024"},
             {"into": "body", "name": "tenant", "value": "${secret:tenant}"}],
            read_secret={"tok": "T", "tenant": "acme"}.__getitem__)
        self.assertEqual(h, {"Authorization": "Bearer T"})
        self.assertEqual(q, [("api-version", "2024")])
        self.assertEqual(b, {"tenant": "acme"})


class _Upstream(BaseHTTPRequestHandler):
    """Records the request it received and returns a canned JSON body."""
    last: dict = {}

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        _Upstream.last = {
            "method": self.command, "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "caller_custom": self.headers.get("X-Caller-Custom"),
            "body": self.rfile.read(length).decode() if length else "",
        }
        payload = b'{"upstream": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _record

    def log_message(self, *a):
        pass


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.up = HTTPServer(("127.0.0.1", 0), _Upstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.addCleanup(self.up.server_close)
        self.addCleanup(self.up.shutdown)
        self.base = f"http://127.0.0.1:{self.up.server_address[1]}"

        self.secrets = tempfile.mkdtemp(prefix="proxy-secrets-")
        self._prev_secrets = http_proxy.SECRETS_DIR
        http_proxy.SECRETS_DIR = self.secrets
        self.addCleanup(lambda: setattr(http_proxy, "SECRETS_DIR", self._prev_secrets))
        _Upstream.last = {}   # reset the shared recorder before each case

    def _start_proxy(self, proxy_cfg: dict) -> str:
        server = HTTPServer(("127.0.0.1", 0), http_proxy._handler(proxy_cfg))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _write_secret(self, name: str, value: str):
        with open(os.path.join(self.secrets, name), "w", encoding="utf-8") as fh:
            fh.write(value)

    def test_injects_auth_and_does_not_forward_caller_headers(self):
        self._write_secret("graph_token", "TOKEN123")
        proxy = self._start_proxy({
            "base_url": self.base,
            "inject": [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:graph_token}"}],
        })
        req = urllib.request.Request(proxy + "/me/messages", method="GET",
                                     headers={"X-Caller-Custom": "sneaky"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(json.loads(resp.read()), {"upstream": "ok"})  # upstream response passed through
        self.assertEqual(_Upstream.last["path"], "/me/messages")          # pinned under base
        self.assertEqual(_Upstream.last["authorization"], "Bearer TOKEN123")  # secret injected
        self.assertIsNone(_Upstream.last["caller_custom"])                # caller header NOT forwarded

    def test_unprovisioned_secret_fails_closed(self):
        proxy = self._start_proxy({  # graph_token referenced but never written
            "base_url": self.base,
            "inject": [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:graph_token}"}],
        })
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(proxy + "/x", timeout=5)
        self.assertEqual(cm.exception.code, 503)   # secret_unavailable, not a leak or a crash
        self.assertEqual(_Upstream.last, {})        # failed closed before any upstream call

    def test_path_escape_is_refused_before_any_upstream_call(self):
        proxy = self._start_proxy({"base_url": self.base + "/v1.0", "inject": []})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(proxy + "/../../admin", timeout=5)
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(_Upstream.last, {})       # never reached the upstream


if __name__ == "__main__":
    unittest.main()
