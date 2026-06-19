"""HTTP transport for the broker.

Binds 127.0.0.1 by default. The boundary depends on this: external agents reach the
broker through a tailnet (e.g. Tailscale Serve) that terminates TLS and proxies to
localhost. The default is deliberately loopback so a bare run cannot expose the broker.

`TOOLSTACK_BROKER_HOST` overrides the bind host. The ONLY supported reason to set it is
running the broker inside a container, where it must bind `0.0.0.0` to be reachable —
and there the boundary moves to Docker's publish mapping (publish to `127.0.0.1:<port>`
on the host ONLY), exactly as tool containers already do via `TOOLSTACK_BIND`. Do not set
it to `0.0.0.0` on a bare host.

Run it:  python3 -m broker.server
"""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from .audit import AuditLog, stderr_sink
from .context import BrokerContext
from .gateway import handle
from .ratelimit import RateLimiter
from .registry import Registry
from .runtime import HttpRuntime
from .store import Store
from .surface_nod import NodSurface

DEFAULT_HOST = "127.0.0.1"  # loopback by default — see the module docstring
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 64 * 1024  # cap request bodies to bound memory use


def _configured_host() -> str:
    # 127.0.0.1 unless explicitly overridden (only for the in-container case).
    return os.environ.get("TOOLSTACK_BROKER_HOST") or DEFAULT_HOST


def _configured_port() -> int:
    raw = os.environ.get("TOOLSTACK_BROKER_PORT")
    if raw is None:
        return DEFAULT_PORT
    try:
        return int(raw)
    except ValueError:
        # Fail loud on a misconfigured port rather than binding a surprise default.
        raise SystemExit(f"TOOLSTACK_BROKER_PORT must be an integer, got {raw!r}")


class _Handler(BaseHTTPRequestHandler):
    # Do not leak the Python/server version to unauthenticated callers.
    server_version = "broker"
    sys_version = ""

    def _ctx(self) -> BrokerContext:
        return self.server.ctx  # type: ignore[attr-defined]

    def _read_body(self):
        """Return the parsed JSON body: {} when absent, None on malformed JSON
        (the gateway maps a non-dict body to 400)."""
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, MAX_BODY_BYTES))
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _respond(self) -> None:
        body = self._read_body()
        response = handle(self.command, self.path, dict(self.headers), body, self._ctx())
        payload = json.dumps(response.body).encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Correlation-Id", response.correlation_id)
        self.end_headers()
        self.wfile.write(payload)

    # Every method goes through the same fail-closed gateway.
    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond
    do_PATCH = _respond

    def log_message(self, *args) -> None:
        # The audit log is our record of requests; suppress the default access log.
        pass


def build_server(
    port: int | None = None,
    db_path: str | None = None,
    audit_sink=stderr_sink,
    registry: Registry | None = None,
    runtime=None,
    tools_root: str | None = None,
    tool_dirs=None,
    surface=None,
    approval_ttl: float | None = None,
    rate_limit: int | None = None,
    host: str | None = None,
) -> HTTPServer:
    bind_host = _configured_host() if host is None else host
    bind_port = _configured_port() if port is None else port
    store = Store(db_path)
    if registry is None:
        registry = Registry.from_sources(tools_root, tool_dirs or ())
    if surface is None:
        surface = NodSurface.from_env()
    if approval_ttl is None:
        approval_ttl = float(os.environ.get("TOOLSTACK_APPROVAL_TTL", "3600"))
    if rate_limit is None:
        rate_limit = int(os.environ.get("TOOLSTACK_RATE_LIMIT", "120"))  # per caller per minute; 0 = off
    ctx = BrokerContext(
        store=store,
        registry=registry,
        runtime=runtime or HttpRuntime(),
        audit=AuditLog(store, sink=audit_sink),
        surface=surface,
        approval_ttl=approval_ttl,
        rate_limiter=RateLimiter(rate_limit),
    )
    server = HTTPServer((bind_host, bind_port), _Handler)
    server.ctx = ctx  # type: ignore[attr-defined]
    return server


def main() -> None:
    logging.basicConfig(level=os.environ.get("TOOLSTACK_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # TOOLSTACK_TOOLS_DIRS is an os.pathsep-separated list of individual tool
    # directories (each holding a toolyard.toml), in addition to the tools root.
    raw_dirs = os.environ.get("TOOLSTACK_TOOLS_DIRS", "")
    tool_dirs = [d for d in raw_dirs.split(os.pathsep) if d]
    server = build_server(
        db_path=os.environ.get("TOOLSTACK_BROKER_DB"),
        tools_root=os.environ.get("TOOLSTACK_TOOLS_ROOT"),
        tool_dirs=tool_dirs,
    )
    host, port = server.server_address
    print(f"broker listening on http://{host}:{port}  (health: GET /v1/health)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.ctx.store.close()  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
