"""Echo tool: a tiny standalone api tool for Toolstack (the tool template).

A tool is its own program. It binds the port the toolyard gives it, serves
``POST /v1/actions/<op>``, and reads its secrets from the cache populated
by the SPS at boot. The runner handed it an ``E_SECRET`` and a CA bundle
in the environment; the tool uses those to talk to SPS over TLS/TCP.

Defense in depth (Phase 4 keeps the channel secret; Phase 2 sources it from
the E_SECRET): if ``$TOOLSTACK_E_SECRET`` is set, the tool requires the
broker's ``X-Toolstack-Secret`` header to match it, so a stray loopback
process can't call this tool directly and bypass the broker's policy.
With no ``TOOLSTACK_E_SECRET`` (e.g. a one-off standalone run), the check
is skipped. See ``verify_broker`` and ``docs/message-contracts.md``.

Stdlib only, so it runs as a bare process or inside a container unchanged.
"""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from sps.tool_sdk import SecretClient

PORT = int(os.environ.get("TOOLSTACK_PORT", "4601"))
# Host process: bind loopback only. In a container, the toolyard sets 0.0.0.0 and
# Docker publishes the port to host loopback via -p 127.0.0.1:<port>.
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")
# Legacy FS path: Phase 5 will remove this entirely (Phase 3's SPS path is
# the production route). Kept here so the in-tree tests continue to work
# during the transition without booting a fake SPS for every test.
SECRETS_DIR = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")


# Phase 3: boot-time SPS lookup. Falls back to FS reads when the env is
# not configured (dev path; Phase 5 will drop this fallback).
try:
    _secrets = SecretClient.from_env("echo_api")
    _secrets_active = True
except RuntimeError:
    _secrets = None
    _secrets_active = False


def _read_secret(name: str) -> str | None:
    """Cache-first with a transient FS fallback (Phase 5 closes this)."""
    if _secrets_active:
        return _secrets.cache_get(name)
    try:
        with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _expected_broker_secret() -> str:
    """The channel credential Phase 4 derives X-Toolstack-Secret from:
    priority TOOLSTACK_E_SECRET (Phase 4); FS broker_secret (Phase 1,
    kept here only for the in-tree SharedSecretE2E tests until Phase 5
    closes the FS path out)."""
    e = os.environ.get("TOOLSTACK_E_SECRET")
    if e:
        return e
    try:
        with open(os.path.join(SECRETS_DIR, "broker_secret"), encoding="utf-8") as f:
            v = f.read().strip()
        return v
    except FileNotFoundError:
        return ""


def verify_broker(headers) -> bool:
    """Defense in depth: compare the request's X-Toolstack-Secret against
    the channel credential the broker was provisioned with. The empty-
    credential branch (no E_SECRET and no broker_secret file) turns the
    feature off entirely, mirroring the broker sending no header."""
    expected = _expected_broker_secret()
    if not expected:
        return True
    presented = headers.get("X-Toolstack-Secret", "")
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def handle_op(op: str, body: dict):
    arguments = body.get("arguments", {})
    if op == "say":
        return {"echoed": arguments}
    if op == "whoami":
        return {
            "caller": body.get("caller", {}).get("name"),
            "broker_request_id": body.get("broker_request_id"),
        }
    if op == "secret_status":
        value = _read_secret("api_key")
        if value is None:
            return {"has_api_key": False}
        return {"has_api_key": True, "api_key_len": len(value)}
    if op == "refresh":
        if not _secrets_active:
            return {"error": "no_sps"}
        _secrets.refresh_all()
        return {"refreshed": list(_secrets.names())}
    if op == "refresh_one":
        if not _secrets_active:
            return {"error": "no_sps"}
        name = arguments.get("name") if isinstance(arguments, dict) else None
        if not name:
            return {"error": "missing 'name' argument"}
        new_value = _secrets.refresh(name)
        return {"refreshed": [name], "len": len(new_value)}
    return None


class _Handler(BaseHTTPRequestHandler):
    server_version = "echo-tool"
    sys_version = ""

    def do_POST(self):
        if not self.path.startswith("/v1/actions/"):
            return self._send(404, {"error": "not_found"})
        if not verify_broker(self.headers):
            return self._send(401, {"error": "unauthorized"})
        op = self.path[len("/v1/actions/"):]
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid"})
        result = handle_op(op, body)
        if result is None:
            return self._send(404, {"error": "unknown_op"})
        self._send(200, result)

    def _send(self, status: int, obj: dict):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main():
    HTTPServer((BIND, PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()
