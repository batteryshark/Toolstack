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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

log = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 30  # opening the upstream connection
_TUNNEL_IDLE = 300  # a CONNECT tunnel with no traffic this long is torn down


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Splice two sockets until either closes or the tunnel goes idle."""
    conns = (a, b)
    while True:
        readable, _, errored = select.select(conns, [], conns, _TUNNEL_IDLE)
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
            try:
                dst.sendall(chunk)
            except OSError:
                return


def _handler(allow: frozenset[str]):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:
            pass  # denials are logged explicitly; don't spam per-request access lines

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
                upstream = socket.create_connection((host, int(port or 443)), _CONNECT_TIMEOUT)
            except OSError:
                return self.send_error(502, f"cannot reach {host}")
            try:
                self.send_response(200, "Connection established")
                self.end_headers()
                self.wfile.flush()
                _pump(self.connection, upstream)
            finally:
                upstream.close()

        def _forward(self) -> None:
            self.close_connection = True
            parts = urlsplit(self.path)
            host = parts.hostname
            if not host or host not in allow:
                return self._deny(host or "?")
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else None
            origin_path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("proxy-connection", "connection", "host")}
            try:
                upstream = http.client.HTTPConnection(host, parts.port or 80, timeout=_CONNECT_TIMEOUT)
                upstream.request(self.command, origin_path, body=body, headers=headers)
                resp = upstream.getresponse()
                data = resp.read()
            except OSError:
                return self.send_error(502, f"cannot reach {host}")
            self.send_response(resp.status)
            for key, value in resp.getheaders():
                # Content-Length is re-derived from the buffered body; hop-by-hop headers drop.
                if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            upstream.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _forward

    return Handler


def serve(port: int, allow) -> ThreadingHTTPServer:
    """Bind the proxy on 127.0.0.1:<port> and return it (caller runs ``serve_forever``)."""
    return ThreadingHTTPServer(("127.0.0.1", port), _handler(frozenset(allow)))


def main() -> None:
    parser = argparse.ArgumentParser(prog="toolyard.egress_proxy")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allow", action="append", default=[],
                        help="allowed destination host (repeatable); matched exactly")
    args = parser.parse_args()
    serve(args.port, args.allow).serve_forever()


if __name__ == "__main__":
    main()
