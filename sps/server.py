"""SPS TLS/TCP server.

The wire protocol: each client opens a TLS connection, sends one JSON
object terminated with `\\n`, and reads one JSON object before closing.
There are no HTTP methods, paths, headers, ALPN, persistent connections,
multiplexing, or binary framing -- JSON-line framing is the entire
message boundary.

The stream handler reads at most 1 MiB through
`socket.makefile().readline()`, and oversized requests are rejected with a
`Bad request` error envelope + close. Per-connection timeout enforced via
`socket.settimeout`.
"""
from __future__ import annotations

import json
import socket
import socketserver
import ssl
from dataclasses import dataclass
from typing import Any

from . import handlers
from .audit import AuditLogger
from .config import Config
from .store import ToolRegistrationStore
from .wire import (
    OversizedBodyError,
    err_envelope,
    read_one_json,
    write_one_json,
)

SOCKET_TIMEOUT = 5.0  # seconds per connection: a slow client cannot hold the server


@dataclass
class AppContext:
    config: Config
    store: ToolRegistrationStore
    audit: AuditLogger
    plugin: Any


_HANDLER_BY_OP = {
    "register": handlers.handle_register,
    "unregister": handlers.handle_unregister,
    "get_secrets": handlers.handle_get_secrets,
    "get_secret": handlers.handle_get_secret,
    "write_secret": handlers.handle_write_secret,
}


class _StreamHandler(socketserver.StreamRequestHandler):
    """One request per connection: read JSON line, dispatch, write JSON
    line, close. No keepalive, no batch, no second message."""

    # Populated by build_server.
    ctx: AppContext = None  # type: ignore[assignment]

    def setup(self) -> None:
        socketserver.StreamRequestHandler.setup(self)
        try:
            self.connection.settimeout(SOCKET_TIMEOUT)
        except OSError:
            pass

    def handle(self) -> None:
        try:
            msg = read_one_json(self.rfile)
        except (OversizedBodyError, ValueError):
            write_one_json(self.wfile, err_envelope("Bad request"))
            return

        if not msg or "op" not in msg or not isinstance(msg.get("op"), str):
            write_one_json(self.wfile, err_envelope("Bad request"))
            return

        op = msg.get("op")
        handler = _HANDLER_BY_OP.get(op)
        if handler is None:
            write_one_json(self.wfile, err_envelope("Bad request"))
            return

        try:
            response = handler(self.ctx, msg)
        except handlers.AuthError:
            write_one_json(self.wfile, err_envelope("Unauthorized"))
            return
        except handlers.BadRegistration:
            write_one_json(self.wfile, err_envelope("Bad request"))
            return
        except handlers.ToolNotFound:
            write_one_json(self.wfile, err_envelope("Not found"))
            return
        except handlers.SecretNotFound:
            write_one_json(self.wfile, err_envelope("Not found"))
            return
        except handlers.NotWritable:
            write_one_json(self.wfile, err_envelope("Not writable"))
            return
        except handlers.BackendError:
            write_one_json(self.wfile, err_envelope("Backend error"))
            return
        except Exception:
            self.ctx.audit.event("internal_error")
            write_one_json(self.wfile, err_envelope("Backend error"))
            return

        write_one_json(self.wfile, response)
        if op in ("get_secrets", "get_secret", "write_secret"):
            self.ctx.audit.event(
                op,
                tool_id=msg.get("toolid", ""),
                secret_name=msg.get("name", ""),
            )


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def build_server(ctx: AppContext, host: str = "127.0.0.1", port: int = 0,
                *, ssl_ctx: ssl.SSLContext | None = None,
                server_class: type = ThreadingTCPServer):
    """Build a TCP server bound to (host, port). Pass `ssl_ctx` for
    production (server-side TLSContext wrapping SPS_TLS_CERT/KEY). For
    in-process tests without TLS, omit `ssl_ctx`."""
    class _Bound(_StreamHandler):
        pass
    _Bound.ctx = ctx
    server = server_class((host, port), _Bound)
    if ssl_ctx is not None:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    return server
