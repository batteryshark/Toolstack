"""Echo-MCP tool — a tiny standalone **streamable-HTTP MCP server** for Toolstack
(the template for a ``type = "mcp"`` tool).

Where the plain echo tool answers ``POST /v1/actions/<op>``, this one speaks MCP: it
serves the streamable-HTTP transport at ``POST /mcp`` and the broker is the MCP
*client*. The broker runs the ``initialize`` handshake, then calls a tool with
``tools/call`` where the MCP tool name IS the toolyard op — so policy/approval still
key on ``echo-mcp.<op>`` exactly like an api tool. The op names here (``say`` /
``whoami``) deliberately mirror the api echo so the two transports are easy to compare.

Everything else is the same tool contract: it binds the port the toolyard gives it,
reads secrets from ``$TOOLSTACK_SECRETS_DIR``, never sees a broker token, and supports
the same optional ``broker_secret`` defense-in-depth check (the ``X-Toolstack-Secret``
header). Broker request context (request id + caller) arrives in the MCP call's
``params._meta`` rather than a JSON body — ``whoami`` reads it from there.

Stdlib only (``http.server``), so it runs as a bare process or in a container unchanged.
"""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRETS_DIR = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")
PORT = int(os.environ.get("TOOLSTACK_PORT", "4611"))
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")
PROTOCOL_VERSION = "2025-06-18"
# A fixed session id is enough to exercise the round-trip: the broker reads it off the
# initialize response and echoes it back on later requests. A real multi-client server
# would mint one per session; this single-purpose demo tool needs only the mechanism.
SESSION_ID = "echo-mcp-session"

# The tools this server exposes. Names match the toolyard ops (the broker calls
# tools/call with name = op). inputSchema is standard JSON Schema, surfaced by tools/list.
TOOLS = [
    {
        "name": "say",
        "description": "Echo the given arguments back.",
        "inputSchema": {
            "type": "object",
            "properties": {"m": {"type": "string", "description": "any value to echo back"}},
        },
    },
    {
        "name": "whoami",
        "description": "Return the calling caller name and broker request id (read from _meta).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def secret(name: str) -> str:
    with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as f:
        return f.read().strip()


def verify_broker(headers) -> bool:
    """Opt-in: if a ``broker_secret`` is provisioned, require the broker's
    ``X-Toolstack-Secret`` header to match it (constant-time). No file (or empty) -> the
    check is off, mirroring the broker sending no header. Same contract as the api echo."""
    try:
        expected = secret("broker_secret")
    except FileNotFoundError:
        return True
    if not expected:
        return True
    presented = headers.get("X-Toolstack-Secret", "")
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def call_tool(name: str, arguments: dict, meta: dict):
    """Run one MCP tool. Returns a plain dict (the structured result) or raises
    KeyError for an unknown tool (mapped to a JSON-RPC method error by the caller)."""
    if name == "say":
        return {"echoed": arguments}
    if name == "whoami":
        caller = (meta.get("caller") or {}).get("name")
        return {"caller": caller, "broker_request_id": meta.get("broker_request_id")}
    raise KeyError(name)


def dispatch(message: dict):
    """Map one JSON-RPC request to a (result_or_None, error_or_None) pair. A
    notification (no ``id``) returns (None, None) — nothing to answer."""
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}

    if msg_id is None:  # a notification (e.g. notifications/initialized) — no reply
        return None, None

    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "echo-mcp", "version": "1.0"},
        }, None

    if method == "tools/list":
        return {"tools": TOOLS}, None

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        meta = params.get("_meta") or {}
        try:
            structured = call_tool(name, arguments, meta)
        except KeyError:
            return None, {"code": -32602, "message": f"unknown tool: {name!r}"}
        # Standard tools/call result: a text content block plus the structured form.
        return {
            "content": [{"type": "text", "text": json.dumps(structured)}],
            "structuredContent": structured,
            "isError": False,
        }, None

    return None, {"code": -32601, "message": f"method not found: {method!r}"}


class _Handler(BaseHTTPRequestHandler):
    server_version = "echo-mcp-tool"
    sys_version = ""

    def do_POST(self):
        if self.path.rstrip("/") != "/mcp":
            return self._send(404, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32601, "message": "not found"}})
        if not verify_broker(self.headers):
            return self._send(401, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32001, "message": "unauthorized"}})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            message = json.loads(self.rfile.read(length)) if length else {}
        except json.JSONDecodeError:
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": "parse error"}})

        result, error = dispatch(message)
        if message.get("id") is None:  # notification -> 202 Accepted, no body
            self.send_response(202)
            self.end_headers()
            return
        envelope = {"jsonrpc": "2.0", "id": message.get("id")}
        if error is not None:
            envelope["error"] = error
        else:
            envelope["result"] = result
        # Pin the session on initialize so the broker can echo it back on later calls.
        extra = {"Mcp-Session-Id": SESSION_ID} if message.get("method") == "initialize" else {}
        self._send(200, envelope, extra)

    def _send(self, status: int, obj: dict, extra_headers: dict | None = None):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main():
    HTTPServer((BIND, PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()
