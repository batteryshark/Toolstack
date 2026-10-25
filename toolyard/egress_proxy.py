"""Egress proxy: the toolyard's outbound-network policy point.

A sandboxed tool has no direct outbound network -- the OS sandbox (Seatbelt, and later
bubblewrap) denies it. When a tool is allowed to reach specific hosts, the runner starts
this per-tool forward proxy on a loopback port, points the tool's HTTP(S)_PROXY at it, and
the sandbox permits outbound only to that one port. The proxy allows a request to a host on
the tool's allowlist and refuses (403) everything else, so the destination policy lives in
one place and reads identically on every OS backend.

    HTTPS: the tool sends `CONNECT host:port`; the proxy checks the host, opens a tunnel,
           and pipes bytes -- it never sees the TLS payload.
    HTTP:  the tool sends an absolute-form request (`GET http://host/..`); the proxy checks
           the host and forwards it in origin form.

Host matching is exact. Run detached by the runner; serves until killed on tool stop:

    python3 -m toolyard.egress_proxy --port <port> --allow <host> [--allow <host> ...]
"""

from __future__ import annotations

import argparse
import http.client
import logging
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

log = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 30  # opening the upstream connection
_TUNNEL_IDLE = 300  # a CONNECT tunnel with no traffic this long is torn down
_TOTAL_DEADLINE = 30
_MAX_BODY = 1024 * 1024
_MAX_RESPONSE = 4 * 1024 * 1024


def _pump(a: socket.socket, b: socket.socket, deadline: float) -> None:
    """Splice two sockets until either closes or the tunnel goes idle."""
    conns = (a, b)
    transferred = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        readable, _, errored = select.select(conns, [], conns, min(_TUNNEL_IDLE, remaining))
        if errored or not readable:  # error or idle timeout
            return
        for src in readable:
            dst = b if src is a else a
            try:
                chunk = src.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            transferred += len(chunk)
            if transferred > _MAX_RESPONSE:
                return
            try:
                dst.sendall(chunk)
            except OSError:
                return


def _handler(allow: frozenset[str]):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)
            self.deadline = time.monotonic() + _TOTAL_DEADLINE
            self.upstream_socket = None
            self.socket_lock = threading.Lock()
            self.expired = False
            def expire():
                with self.socket_lock:
                    self.expired = True
                    for connection in (self.connection, self.upstream_socket):
                        if connection is not None:
                            try:
                                connection.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
            self.timer = threading.Timer(_TOTAL_DEADLINE, expire)
            self.timer.daemon = True
            self.timer.start()

        def finish(self):
            self.timer.cancel()
            self.timer.join()
            super().finish()

        def _remaining(self):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.expired:
                raise TimeoutError("egress deadline")
            return min(5, remaining)

        def _connect(self, address):
            # OS DNS is synchronous and cannot be preempted here. Resolve first,
            # then refuse late completion BEFORE connect or any request bytes.
            self._remaining()
            addresses = socket.getaddrinfo(*address, type=socket.SOCK_STREAM)
            self._remaining()
            for family, kind, proto, _, sockaddr in addresses:
                upstream = socket.socket(family, kind, proto)
                try:
                    # Publish before connect under the expiry lock: the timer
                    # cannot miss a newly connected/published socket.
                    with self.socket_lock:
                        upstream.settimeout(self._remaining())
                        self.upstream_socket = upstream
                    upstream.connect(sockaddr)
                    upstream.settimeout(self._remaining())
                    return upstream
                except OSError:
                    upstream.close()
                    self._remaining()
            raise OSError("upstream failed")

        def log_message(self, *args) -> None:
            pass  # denials are logged explicitly; don't spam per-request access lines

        def send_error(self, *args, **kwargs):
            try:
                super().send_error(*args, **kwargs)
            except OSError:
                self.close_connection = True  # deadline/disconnected peer: best effort

        def _deny(self, host: str) -> None:
            log.warning("egress denied: %s not in allowlist", host)
            self.close_connection = True
            body = b"egress denied by policy"
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_CONNECT(self) -> None:
            self.close_connection = True
            host, _, port = self.path.partition(":")
            if host not in allow:
                return self._deny(host)
            try:
                upstream = self._connect((host, int(port or 443)))
            except (OSError, ValueError):
                return self.send_error(502, "upstream failed")
            try:
                self._remaining()
                self.send_response(200, "Connection established")
                self.end_headers()
                self.wfile.flush()
                _pump(self.connection, upstream, self.deadline)
            except OSError:
                pass  # expired/disconnected tunnel; never expose exception details
            finally:
                upstream.close()

        def _forward(self) -> None:
            self.close_connection = True
            parts = urlsplit(self.path)
            host = parts.hostname
            if not host or host not in allow:
                return self._deny(host or "?")
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
                return self.send_error(400, "unsupported request framing")
            raw_length = lengths[0] if lengths else "0"
            if not raw_length.isascii() or not raw_length.isdecimal():
                return self.send_error(400, "invalid content length")
            if len(raw_length) > 10 or int(raw_length) > _MAX_BODY:
                return self.send_error(413, "request too large")
            length = int(raw_length)
            body = self.rfile.read(length) if length else None
            if length and len(body) != length:
                return self.send_error(400, "incomplete request body")
            if parts.scheme != "http" or parts.username or parts.password:
                return self.send_error(400, "HTTP absolute URL required")
            origin_path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("proxy-connection", "connection", "host")}
            upstream = None
            resp = None
            started = False
            try:
                upstream = http.client.HTTPConnection(host, parts.port or 80,
                    timeout=self._remaining())
                upstream.sock = self._connect((host, parts.port or 80))
                # Never allow HTTPConnection to reconnect after expiry.
                upstream.auto_open = 0
                upstream.sock.settimeout(self._remaining())
                upstream.request(self.command, origin_path, body=body, headers=headers)
                upstream.sock.settimeout(self._remaining())
                resp = upstream.getresponse()
                announced = resp.getheader("Content-Length")
                if announced and (not announced.isdecimal() or int(announced) > _MAX_RESPONSE):
                    return self.send_error(502, "upstream response too large")
                self.send_response(resp.status)
                for key, value in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection", "content-length", "keep-alive", "upgrade", "trailer"):
                        self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
                started = True
                total = 0
                while self.command != "HEAD":
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        return
                    if upstream.sock:
                        upstream.sock.settimeout(min(5, remaining))
                    chunk = resp.read1(min(65536, _MAX_RESPONSE - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_RESPONSE:
                        return
                    self.wfile.write(chunk)
            except (OSError, ValueError, http.client.HTTPException):
                if not started:
                    self.send_error(502, "upstream failed")
            finally:
                if resp is not None:
                    resp.close()
                if upstream:
                    upstream.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _forward

    return Handler


class BoundedProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def serve(port: int, allow) -> ThreadingHTTPServer:
    """Bind the proxy on 127.0.0.1:<port> and return it (caller runs ``serve_forever``)."""
    return BoundedProxyServer(("127.0.0.1", port), _handler(frozenset(allow)))


def main() -> None:
    parser = argparse.ArgumentParser(prog="toolyard.egress_proxy")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allow", action="append", default=[],
                        help="allowed destination host (repeatable); matched exactly")
    args = parser.parse_args()
    serve(args.port, args.allow).serve_forever()


if __name__ == "__main__":
    main()
