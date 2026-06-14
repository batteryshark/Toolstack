"""Echo tool — a tiny standalone REST tool for Toolstack (the tool template).

A tool is its own program. It binds the port the toolyard gives it, serves
``POST /v1/actions/<op>``, and reads its secrets from files under
``$TOOLSTACK_SECRETS_DIR`` (default ``/run/secrets``). It never receives or needs a
broker token or a secret-backend credential — the broker forwards the call; the
toolyard already placed this tool's secrets where it can read them.

Stdlib only, so it runs as a bare process or inside a container unchanged.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRETS_DIR = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")
PORT = int(os.environ.get("TOOLSTACK_PORT", "4601"))
# Host process: bind loopback only. In a container, the toolyard sets 0.0.0.0 and
# Docker publishes the port to host loopback via -p 127.0.0.1:<port>.
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")


def secret(name: str) -> str:
    with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as f:
        return f.read().strip()


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
        # Prove we can read our own secret WITHOUT returning its value.
        try:
            value = secret("api_key")
        except FileNotFoundError:
            return {"has_api_key": False}
        return {"has_api_key": bool(value), "api_key_len": len(value)}
    return None  # unknown op


class _Handler(BaseHTTPRequestHandler):
    server_version = "echo-tool"
    sys_version = ""

    def do_POST(self):
        if not self.path.startswith("/v1/actions/"):
            return self._send(404, {"error": "not_found"})
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
