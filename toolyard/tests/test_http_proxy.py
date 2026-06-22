"""toolyard.http_proxy: the generic REST proxy tool.

Covers the security spine as pure functions (base_url pinning, secret injection) plus one
end-to-end run through a real proxy server against a fake upstream: the injected auth goes
out, the caller's own headers do NOT, an unprovisioned secret fails closed, and a path that
tries to escape the base_url is refused. A final group exercises the opt-in rotation control
plane end to end against the real toolyard write-proxy.
"""

import json
import os
import socket
import tempfile
import threading
import tomllib
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from toolyard import http_proxy, write_proxy
from toolyard.config import SecretSpec, ToolDef
from toolyard.secrets import FileBackend


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

    do_GET = do_POST = do_PUT = _record

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
        cm.exception.close()
        self.assertEqual(_Upstream.last, {})        # failed closed before any upstream call

    def test_path_escape_is_refused_before_any_upstream_call(self):
        proxy = self._start_proxy({"base_url": self.base + "/v1.0", "inject": []})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(proxy + "/../../admin", timeout=5)
        self.assertEqual(cm.exception.code, 400)
        cm.exception.close()
        self.assertEqual(_Upstream.last, {})       # never reached the upstream

    def test_forward_headers_lets_allowlisted_caller_headers_through(self):
        self._write_secret("graph_token", "TOKEN123")
        proxy = self._start_proxy({
            "base_url": self.base,
            "inject": [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:graph_token}"}],
            "forward_headers": ["X-Caller-Custom"],
        })
        req = urllib.request.Request(proxy + "/x", method="GET", headers={"X-Caller-Custom": "let-me-in"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        self.assertEqual(_Upstream.last["caller_custom"], "let-me-in")        # allowlisted -> forwarded
        self.assertEqual(_Upstream.last["authorization"], "Bearer TOKEN123")  # injected auth intact

    def test_forwarded_header_cannot_override_injected_auth(self):
        # load_proxy_config would reject forward_headers=["Authorization"]; this exercises the
        # runtime guard directly (belt-and-suspenders): a caller's Authorization is still dropped.
        self._write_secret("graph_token", "TOKEN123")
        proxy = self._start_proxy({
            "base_url": self.base,
            "inject": [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:graph_token}"}],
            "forward_headers": ["Authorization"],
        })
        req = urllib.request.Request(proxy + "/x", method="GET", headers={"Authorization": "Bearer EVIL"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        self.assertEqual(_Upstream.last["authorization"], "Bearer TOKEN123")  # injected wins, caller dropped

    def test_obs_fold_in_forwarded_value_is_refused(self):
        # urllib permits obs-fold ("CRLF + space"); a raw caller value with it would smuggle a
        # header line into the authenticated upstream request. The proxy must refuse it.
        self._write_secret("graph_token", "TOKEN123")
        proxy = self._start_proxy({
            "base_url": self.base,
            "inject": [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:graph_token}"}],
            "forward_headers": ["X-Caller-Custom"],
        })
        port = int(proxy.rsplit(":", 1)[1])
        raw = (b"GET /x HTTP/1.1\r\nHost: proxy\r\n"
               b"X-Caller-Custom: aaa\r\n bbb-smuggled\r\n"   # obs-fold continuation line
               b"Connection: close\r\n\r\n")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(raw)
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        self.assertEqual(resp.split(b" ", 2)[1], b"400")   # bad_forward_header
        self.assertEqual(_Upstream.last, {})               # never reached the upstream

    def test_base_url_secret_in_path_is_substituted(self):
        self._write_secret("account", "acct-42")
        proxy = self._start_proxy({"base_url": self.base + "/${secret:account}/v1", "inject": []})
        with urllib.request.urlopen(proxy + "/items", timeout=5) as resp:
            resp.read()
        self.assertEqual(_Upstream.last["path"], "/acct-42/v1/items")   # secret filled the path prefix

    def test_empty_base_url_secret_fails_closed(self):
        # a misprovisioned (empty) account secret would collapse the confining prefix to root;
        # the proxy must fail closed, not widen the caller's reach to the whole host.
        self._write_secret("account", "")
        proxy = self._start_proxy({"base_url": self.base + "/${secret:account}", "inject": []})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(proxy + "/admin", timeout=5)
        self.assertEqual(cm.exception.code, 503)
        cm.exception.close()
        self.assertEqual(_Upstream.last, {})   # no unconfined upstream call


class Rotation(unittest.TestCase):
    """The opt-in rotation control plane: PUT <control_prefix>/<name> {value} writes a writable
    secret back through the REAL toolyard write-proxy, gated by `rotatable`, never forwarded
    upstream, and never echoing the value."""

    def setUp(self):
        # a real upstream recorder, only to prove a control request never reaches it
        self.up = HTTPServer(("127.0.0.1", 0), _Upstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.addCleanup(self.up.server_close)
        self.addCleanup(self.up.shutdown)
        self.base = f"http://127.0.0.1:{self.up.server_address[1]}"
        _Upstream.last = {}

        # the real write-proxy over a Unix socket, backed by a temp secrets.toml
        self.secrets_file = Path(tempfile.mkdtemp(prefix="proxy-rot-")) / "secrets.toml"
        self.secrets_file.write_text('[demo]\nTOKEN = "old"\nRO = "keep"\n')
        tool = ToolDef(id="demo", type="rest", port=1, command=None, image=None,
                       secrets=(SecretSpec("token", "TOKEN", writable=True),
                                SecretSpec("ro", "RO", writable=False)),
                       path=Path("."))
        self.sock = str(Path(tempfile.mkdtemp(prefix="proxy-rot-sock-")) / "secrets.sock")
        self.wp = write_proxy.serve(self.sock, tool, FileBackend(self.secrets_file))
        threading.Thread(target=self.wp.serve_forever, daemon=True).start()
        self.addCleanup(self.wp.server_close)
        self.addCleanup(self.wp.shutdown)

        self._prev_sock = os.environ.get("TOOLYARD_SECRETS_SOCKET")
        os.environ["TOOLYARD_SECRETS_SOCKET"] = self.sock
        self.addCleanup(self._restore_sock)

        # an empty secrets dir so _verify_broker finds no broker_secret (check is off)
        self._prev_secrets = http_proxy.SECRETS_DIR
        http_proxy.SECRETS_DIR = tempfile.mkdtemp(prefix="proxy-rot-secdir-")
        self.addCleanup(lambda: setattr(http_proxy, "SECRETS_DIR", self._prev_secrets))

    def _restore_sock(self):
        if self._prev_sock is None:
            os.environ.pop("TOOLYARD_SECRETS_SOCKET", None)
        else:
            os.environ["TOOLYARD_SECRETS_SOCKET"] = self._prev_sock

    def _start_proxy(self, proxy_cfg: dict) -> str:
        server = HTTPServer(("127.0.0.1", 0), http_proxy._handler(proxy_cfg))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _token(self) -> str:
        with self.secrets_file.open("rb") as fh:
            return tomllib.load(fh)["demo"]["TOKEN"]

    def test_put_rotates_secret_and_does_not_forward_upstream(self):
        proxy = self._start_proxy({"base_url": self.base, "rotatable": ["token"]})
        req = urllib.request.Request(proxy + "/.toolstack/secret/token", method="PUT",
                                     data=json.dumps({"value": "new-token"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = resp.read()
        self.assertEqual(json.loads(payload), {"ok": True, "rotated": "token"})
        self.assertNotIn(b"new-token", payload)        # the value is never echoed back
        self.assertEqual(self._token(), "new-token")   # written through the write-proxy
        self.assertEqual(_Upstream.last, {})           # never forwarded upstream

    def test_non_rotatable_name_is_forbidden(self):
        # `ro` is writable in the write-proxy but NOT in `rotatable`, so the proxy blocks it first
        proxy = self._start_proxy({"base_url": self.base, "rotatable": ["token"]})
        req = urllib.request.Request(proxy + "/.toolstack/secret/ro", method="PUT",
                                     data=json.dumps({"value": "hijack"}).encode())
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 403)
        cm.exception.close()
        self.assertEqual(self._token(), "old")   # nothing written

    def test_rotate_requires_put(self):
        proxy = self._start_proxy({"base_url": self.base, "rotatable": ["token"]})
        req = urllib.request.Request(proxy + "/.toolstack/secret/token", method="POST",
                                     data=json.dumps({"value": "x"}).encode())
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 405)
        cm.exception.close()
        self.assertEqual(_Upstream.last, {})   # a POST to the control path is not a passthrough

    def test_rotate_rejects_empty_value(self):
        proxy = self._start_proxy({"base_url": self.base, "rotatable": ["token"]})
        req = urllib.request.Request(proxy + "/.toolstack/secret/token", method="PUT", data=b"{}")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 400)
        cm.exception.close()
        self.assertEqual(self._token(), "old")

    def test_rotate_rejects_oversized_value(self):
        proxy = self._start_proxy({"base_url": self.base, "rotatable": ["token"]})
        big = json.dumps({"value": "x" * (64 * 1024 + 1)}).encode()
        req = urllib.request.Request(proxy + "/.toolstack/secret/token", method="PUT", data=big)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 413)
        cm.exception.close()
        self.assertEqual(self._token(), "old")   # nothing written

    def test_control_path_is_inert_without_rotatable(self):
        # with no `rotatable` the control prefix is just a normal path: forwarded and pinned
        proxy = self._start_proxy({"base_url": self.base, "inject": []})
        req = urllib.request.Request(proxy + "/.toolstack/secret/token", method="PUT",
                                     data=json.dumps({"value": "x"}).encode())
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        self.assertEqual(_Upstream.last["path"], "/.toolstack/secret/token")   # forwarded as-is


class LoadConfig(unittest.TestCase):
    """`load_proxy_config` validates the [proxy] block, including the rotatable allowlist's
    charset (so a bad name can never reach the write-proxy request line)."""

    def _write(self, body: str) -> str:
        path = Path(tempfile.mkdtemp(prefix="proxy-cfg-")) / "toolyard.toml"
        path.write_text(body)
        return str(path)

    def test_rejects_rotatable_name_outside_charset(self):
        cfg = self._write('[proxy]\nbase_url = "https://api.example.com"\nrotatable = ["tok en"]\n')
        with self.assertRaises(SystemExit):
            http_proxy.load_proxy_config(cfg)

    def test_accepts_valid_rotatable(self):
        cfg = self._write('[proxy]\nbase_url = "https://api.example.com"\nrotatable = ["graph_token"]\n')
        self.assertEqual(http_proxy.load_proxy_config(cfg)["rotatable"], ["graph_token"])

    def test_rejects_forwarding_reserved_header(self):
        cfg = self._write('[proxy]\nbase_url = "https://api.example.com"\nforward_headers = ["Authorization"]\n')
        with self.assertRaises(SystemExit):
            http_proxy.load_proxy_config(cfg)

    def test_rejects_forwarding_framing_header(self):
        cfg = self._write('[proxy]\nbase_url = "https://api.example.com"\nforward_headers = ["Transfer-Encoding"]\n')
        with self.assertRaises(SystemExit):
            http_proxy.load_proxy_config(cfg)

    def test_rejects_base_url_secret_in_host(self):
        cfg = self._write('[proxy]\nbase_url = "https://${secret:host}.example.com/v1"\n')
        with self.assertRaises(SystemExit):
            http_proxy.load_proxy_config(cfg)

    def test_accepts_base_url_secret_in_path(self):
        cfg = self._write('[proxy]\nbase_url = "https://api.example.com/${secret:acct}/v1"\n')
        self.assertEqual(http_proxy.load_proxy_config(cfg)["base_url"],
                         "https://api.example.com/${secret:acct}/v1")


if __name__ == "__main__":
    unittest.main()
