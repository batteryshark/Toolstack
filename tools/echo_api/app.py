"""Echo tool: a tiny standalone api tool for Toolstack (the tool template).

A tool is its own program. It binds the port the toolyard gives it, serves
``POST /v1/actions/<op>``, and reads its secrets from the cache populated
by the SPS at boot. The runner handed it an ``E_SECRET`` and a CA bundle
in the environment; the tool uses those to talk to SPS over TLS/TCP.

Defense in depth (Phase 4): if ``$TOOLSTACK_E_SECRET`` is set, the tool
requires the broker's ``X-Toolstack-Secret`` header to match it, so a
stray loopback process can't call this tool directly and bypass the
broker's policy. With no ``TOOLSTACK_E_SECRET`` (e.g. a one-off standalone
run), the check is skipped.

Stdlib only, so it runs as a bare process or inside a container unchanged.
"""

import hmac
import json
import os
import tomllib
from http.server import BaseHTTPRequestHandler, HTTPServer

from sps.tool_sdk import SecretClient

PORT = int(os.environ.get("TOOLSTACK_PORT", "4601"))
# Host process: bind loopback only. In a container, the toolyard sets 0.0.0.0 and
# Docker publishes the port to host loopback via -p 127.0.0.1:<port>.
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")


def _tool_id_from_config() -> str:
    """Read the canonical tool id from the toml the runner mounted at
    ``$TOOLSTACK_TOOL_CONFIG``. The runner registers this same id with SPS, so
    the value the tool passes to ``SecretClient.from_env`` always matches the
    SPS-side registration (no drift between the hardcoded id and the toml id).
    """
    path = os.environ.get("TOOLSTACK_TOOL_CONFIG", "")
    if not path:
        raise RuntimeError(
            "TOOLSTACK_TOOL_CONFIG is not set; cannot determine tool id"
        )
    with open(path, "rb") as f:
        return tomllib.load(f)["id"]


# Boot the SPS-backed secret cache. SPS is the production route; without
# it the tool runs in "no secrets" mode and `secret_status` reports that.
_secrets = SecretClient.from_env(_tool_id_from_config())


def verify_broker(headers) -> bool:
    """Defense in depth: compare X-Toolstack-Secret against the E_SECRET the
    runner minted for this tool. No E_SECRET env -> feature off."""
    expected = os.environ.get("TOOLSTACK_E_SECRET") or ""
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
        value = _secrets.cache_get("api_key")
        if value is None:
            return {"has_api_key": False}
        return {"has_api_key": True, "api_key_len": len(value)}
    if op == "refresh":
        _secrets.refresh_all()
        return {"refreshed": list(_secrets.names())}
    if op == "refresh_one":
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
