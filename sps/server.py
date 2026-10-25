"""SPS TLS/TCP server.

The wire protocol: each client opens a TLS connection, sends one JSON
object terminated with `\\n`, and reads one JSON object before closing.
There are no HTTP methods, paths, headers, ALPN, persistent connections,
multiplexing, or binary framing -- JSON-line framing is the entire
message boundary.

The stream handler reads at most 1 MiB with an absolute body deadline.
Oversized requests are rejected with a `Bad request` error envelope + close.
TLS negotiation is admitted to a bounded worker pool, never run on accept.
"""
from __future__ import annotations

import json
import socket
import socketserver
import ssl
import threading
import hashlib
import time
import select
from dataclasses import dataclass
from typing import Any

from . import handlers
from .audit import AuditLogger
from .config import Config, validate_listener
from .store import ToolRegistrationStore
from .wire import (
    OversizedBodyError,
    MESSAGE_SET,
    err_envelope,
    read_socket_json,
    write_one_json,
)

SOCKET_TIMEOUT = 5.0  # seconds per connection: a slow client cannot hold the server
BODY_TIMEOUT = 5.0  # absolute JSON-line read budget, not reset by dribbled bytes


def handshake_with_deadline(request, timeout):
    """Nonblocking TLS progress shares one absolute deadline."""
    deadline = time.monotonic() + timeout
    request.setblocking(False)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TLS handshake deadline exceeded")
            try:
                request.do_handshake()
                if time.monotonic() >= deadline:
                    raise TimeoutError("TLS handshake deadline exceeded")
                return
            except ssl.SSLWantReadError:
                readers, writers = [request], []
            except ssl.SSLWantWriteError:
                readers, writers = [], [request]
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not any(select.select(readers, writers, [], remaining)[:2]):
                raise TimeoutError("TLS handshake deadline exceeded")
    finally:
        request.settimeout(SOCKET_TIMEOUT)


@dataclass
class AppContext:
    config: Config
    store: ToolRegistrationStore
    audit: AuditLogger
    plugin: Any
    boot_id: str


_HANDLER_BY_OP = {
    "ping": handlers.handle_ping,
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
        msg = {}
        op = "invalid"
        try:
            msg = read_socket_json(self.connection, timeout=BODY_TIMEOUT)
            self.connection.settimeout(SOCKET_TIMEOUT)
            if not isinstance(msg, dict) or not isinstance(msg.get("op"), str):
                raise ValueError("invalid envelope")
            op = msg["op"] if msg["op"] in _HANDLER_BY_OP else "invalid"
            handler = _HANDLER_BY_OP.get(op)
            if handler is None:
                raise ValueError("unknown op")
            try:
                response = handler(self.ctx, msg)
            except ValueError as exc:
                raise handlers.BackendError("invalid backend result") from exc
        except handlers.AuthError:
            response = err_envelope("Unauthorized")
        except (handlers.BadRegistration, ValueError):
            response = err_envelope("Bad request")
        except (handlers.ToolNotFound, handlers.SecretNotFound):
            response = err_envelope("Not found")
        except handlers.NotWritable:
            response = err_envelope("Not writable")
        except handlers.BackendError:
            response = err_envelope("Backend error")
        except (TimeoutError, OSError):
            self.connection.settimeout(SOCKET_TIMEOUT)
            response = err_envelope("Bad request")
        except Exception:
            response = err_envelope("Backend error")
        finally:
            # read_socket_json changes the timeout even on malformed input.
            self.connection.settimeout(SOCKET_TIMEOUT)
        # Fail closed on audit failure: do not release values or a success reply.
        # A completed backend mutation cannot be rolled back; callers must not
        # automatically replay after a lost/error response.
        try:
            def identity(key):
                value = msg.get(key) if isinstance(msg, dict) else None
                return ("sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
                        if isinstance(value, str) and value else "")
            outcome = ("ok" if response.get("status") == "ok" else
                       response.get("message"))
            if outcome not in MESSAGE_SET and outcome != "ok":
                outcome = "Backend error"
            if op in ("ping", "invalid") or outcome in ("Bad request", "Unauthorized"):
                self.server._record_reject("ping" if op == "ping" else "invalid")
            else:
                extra = {}
                if op == "register" and outcome == "ok":
                    entries = msg["secrets"]
                    digest = lambda value: "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
                    extra = {"entries": [{"field": digest(e["field"]),
                                          "item": digest(e.get("item") or msg["toolid"])}
                                         for e in entries],
                             "entry_count": len(entries),
                             "writable_count": sum(e.get("writable", False) for e in entries)}
                self.ctx.audit.event(op, outcome=outcome,
                                     tool_id=identity("toolid"), secret_name=identity("name"), **extra)
        except Exception:
            response = err_envelope("Backend error")
        try:
            write_one_json(self.wfile, response)
        except OSError:
            pass  # disconnected peer: never emit request/exception tracebacks


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, max_workers=32, **kwargs):
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.request_queue_size = max(self.request_queue_size, max_workers)
        self._slots = threading.BoundedSemaphore(max_workers)
        self._reject_lock = threading.Lock()
        self._rejects = {"admission": 0, "transport": 0, "ping": 0, "invalid": 0}
        self._last_reject_audit = float("-inf")
        self.ssl_ctx = None
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            self._record_reject("admission")
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            self._flush_rejects()
            request.settimeout(SOCKET_TIMEOUT)
            if self.ssl_ctx is not None:
                request = self.ssl_ctx.wrap_socket(request, server_side=True,
                                                   do_handshake_on_connect=False)
                handshake_with_deadline(request, SOCKET_TIMEOUT)
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            self._record_reject("transport")
            self.shutdown_request(request)
        finally:
            self._flush_rejects()
            self._slots.release()

    def _record_reject(self, kind):
        # Constant-space saturating counters only: no disk I/O on accept.
        with self._reject_lock:
            self._rejects[kind] = min(self._rejects[kind] + 1, 2**31 - 1)

    def _flush_rejects(self):
        # Best-effort operational summaries, at most four writes/second across
        # all workers. Counts saturate and may be lost on failure/exit; these
        # are not durable per-rejection application audit records.
        with self._reject_lock:
            now = time.monotonic()
            if now - self._last_reject_audit < 1 or not any(self._rejects.values()):
                return
            counts = self._rejects.copy()
            self._rejects = dict.fromkeys(counts, 0)
            self._last_reject_audit = now
        for kind, count in counts.items():
            if count:
                try:
                    self.RequestHandlerClass.ctx.audit.event(
                        kind, outcome="rejected", count=count)
                except Exception:
                    pass

    def handle_error(self, request, client_address):
        # socketserver's default prints exception text/tracebacks. Nothing
        # request-derived belongs on stderr, including disconnect failures.
        pass


def build_server(ctx: AppContext, host: str = "127.0.0.1", port: int = 0,
                *, ssl_ctx: ssl.SSLContext | None = None,
                server_class: type = ThreadingTCPServer,
                allow_plaintext_for_tests: bool = False):
    """Build a bounded TCP server. TLS handshakes run inside admitted workers.
    Plaintext requires the explicit allow_plaintext_for_tests opt-in."""
    if ssl_ctx is None and not allow_plaintext_for_tests:
        raise ValueError("SPS requires TLS; plaintext is test-only")
    validate_listener(host, getattr(getattr(ctx, "config", None), "sp_allow_nonloopback", False))
    if not issubclass(server_class, ThreadingTCPServer):
        raise ValueError("SPS requires bounded handshake worker server")
    class _Bound(_StreamHandler):
        pass
    _Bound.ctx = ctx
    server = server_class((host, port), _Bound)
    server.ssl_ctx = ssl_ctx
    return server
