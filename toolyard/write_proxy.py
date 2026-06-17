"""Writable-secret proxy — the toolyard side of message-contracts §4.

A tool that refreshes a credential (e.g. an OAuth token) cannot reach the secret
backend itself. Instead it `POST`s the new value to a Unix socket the toolyard
mounts into the container at `/run/toolyard/secrets.sock`; this proxy — which runs
on the host, holds the backend, and is never inside the container — enforces the
tool's writable allowlist and patches exactly the declared `(vault, item, field)`.

Wire shape (what the tool sends):

    POST /v1/secrets/<name> HTTP/1.1
    Content-Type: application/json

    {"value": "<new value>", "reason": "<audit reason>"}

Run as a detached process by the runner; it serves until killed on tool stop:

    python3 -m toolyard.write_proxy --socket <path> --toml <toolyard.toml> \
        --secret-backend file|infisical [--secrets-file <path>]
"""

from __future__ import annotations

import argparse
import json
import os
import socketserver
from pathlib import Path

from .config import ToolDef, load
from .secrets import get_backend, writable_spec

_PREFIX = "/v1/secrets/"


def _handler(tool_def: ToolDef, backend):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            try:
                self._handle()
            except Exception:  # never let one bad request kill the server
                self._reply(500, {"error": "internal"})

        def _handle(self) -> None:
            request_line = self.rfile.readline().decode("latin-1").strip()
            parts = request_line.split()
            if len(parts) < 2:
                return self._reply(400, {"error": "bad_request"})
            method, path = parts[0], parts[1]
            length = 0
            while True:
                line = self.rfile.readline().decode("latin-1")
                if line in ("\r\n", "\n", ""):
                    break
                key, _, value = line.partition(":")
                if key.strip().lower() == "content-length":
                    length = int(value.strip() or 0)
            body = self.rfile.read(length) if length else b""

            if method != "POST" or not path.startswith(_PREFIX):
                return self._reply(404, {"error": "not_found"})
            name = path[len(_PREFIX):]
            try:
                payload = json.loads(body or b"{}")
            except json.JSONDecodeError:
                return self._reply(400, {"error": "invalid_json"})
            value = payload.get("value")
            if not isinstance(value, str):
                return self._reply(400, {"error": "value must be a string"})

            try:
                writable_spec(tool_def, name)  # allowlist check (raises if not allowed)
            except PermissionError:
                return self._reply(403, {"error": "not_writable"})
            except KeyError:
                return self._reply(404, {"error": "unknown_secret"})
            try:
                backend.update(tool_def, name, value)
            except Exception as exc:
                return self._reply(502, {"error": f"backend_update_failed: {exc}"})
            self._reply(200, {"ok": True, "name": name})

        def _reply(self, status: int, obj: dict) -> None:
            payload = json.dumps(obj).encode("utf-8")
            reason = {200: "OK", 400: "Bad Request", 403: "Forbidden",
                      404: "Not Found", 500: "Internal Server Error",
                      502: "Bad Gateway"}.get(status, "OK")
            self.wfile.write(
                f"HTTP/1.1 {status} {reason}\r\n".encode()
                + b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + payload
            )

    return Handler


def serve(socket_path: str | Path, tool_def: ToolDef, backend) -> socketserver.UnixStreamServer:
    """Bind the socket and return a server (caller runs ``serve_forever``)."""
    path = Path(socket_path)
    if path.exists():
        path.unlink()
    server = socketserver.ThreadingUnixStreamServer(str(path), _handler(tool_def, backend))
    os.chmod(path, 0o666)  # the container user (non-root) must be able to connect
    return server


def main() -> None:
    parser = argparse.ArgumentParser(prog="toolyard.write_proxy")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--toml", required=True, help="path to the tool's toolyard.toml")
    parser.add_argument("--secret-backend", default=os.environ.get("TOOLSTACK_SECRET_BACKEND", "file"))
    parser.add_argument("--secrets-file")
    args = parser.parse_args()
    tool_def = load(args.toml)
    backend = get_backend(args.secret_backend, secrets_file=args.secrets_file)
    serve(args.socket, tool_def, backend).serve_forever()


if __name__ == "__main__":
    main()
