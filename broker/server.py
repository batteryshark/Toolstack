"""HTTP transport for the broker.

Binds 127.0.0.1 by default. The boundary depends on this: external agents reach the
broker through a tailnet (e.g. Tailscale Serve) that terminates TLS and proxies to
localhost. The default is deliberately loopback so a bare run cannot expose the broker.

`TOOLSTACK_BROKER_HOST` overrides the bind host. The ONLY supported reason to set it is
running the broker inside a container, where it must bind `0.0.0.0` to be reachable,
and there the boundary moves to Docker's publish mapping (publish to `127.0.0.1:<port>`
on the host ONLY), exactly as tool containers already do via `TOOLSTACK_BIND`. Do not set
it to `0.0.0.0` on a bare host.

Run it:  python3 -m broker.server
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import uuid
import io
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .audit import AuditLog, stderr_sink
from .context import BrokerContext
from .gateway import handle
from .ratelimit import RateLimiter
from .registry import Registry
from .runtime import HttpRuntime
from .store import Store
from .surface_nod import NodSurface
from .bounds import DeadlineReader

DEFAULT_HOST = "127.0.0.1"  # loopback by default, see the module docstring
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 64 * 1024  # cap request bodies to bound memory use
DEFAULT_REST_BODY_MAX = 20 * 1024 * 1024
INPUT_TOTAL_SECONDS = 10.0
INPUT_IDLE_SECONDS = 3.0
OUTPUT_TOTAL_SECONDS = 10.0
OUTPUT_WRITE_SECONDS = 3.0  # conservative total per sendall, not a throughput guarantee
MAX_HEADER_BYTES = 64 * 1024


class _HeaderTooLarge(ValueError):
    pass


class _InputReader(io.BufferedReader):
    # readline is used for the request line and headers; body uses read().
    def __init__(self, raw):
        super().__init__(raw)
        self.header_remaining = MAX_HEADER_BYTES

    def readline(self, size=-1):
        cap = self.header_remaining + 1
        line = super().readline(min(size, cap) if size >= 0 else cap)
        self.header_remaining -= len(line)
        if self.header_remaining < 0:
            raise _HeaderTooLarge()
        return line


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _configured_host() -> str:
    # 127.0.0.1 unless explicitly overridden. A non-loopback bind exposes the broker to the
    # network, so it fails closed unless TOOLSTACK_BROKER_ALLOW_NONLOOPBACK=1 is also set (the
    # container sets it; there the boundary is Docker's publish-to-127.0.0.1 mapping).
    host = os.environ.get("TOOLSTACK_BROKER_HOST") or DEFAULT_HOST
    allow = os.environ.get("TOOLSTACK_BROKER_ALLOW_NONLOOPBACK", "").lower() in ("1", "true", "yes")
    if not _is_loopback(host) and not allow:
        raise SystemExit(
            f"refusing to bind the broker to non-loopback host {host!r} without "
            "TOOLSTACK_BROKER_ALLOW_NONLOOPBACK=1. Binding off 127.0.0.1 exposes the broker to "
            "the network; set it only behind a boundary you trust (e.g. Docker's publish mapping).")
    return host


def _configured_port() -> int:
    raw = os.environ.get("TOOLSTACK_BROKER_PORT")
    if raw is None:
        return DEFAULT_PORT
    try:
        return int(raw)
    except ValueError:
        # Fail loud on a misconfigured port rather than binding a surprise default.
        raise SystemExit(f"TOOLSTACK_BROKER_PORT must be an integer, got {raw!r}")


def _state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "toolstack"


def _pidfile_path() -> Path:
    return _state_dir() / "broker.pid"


def _write_pidfile() -> None:
    path = _pidfile_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()), encoding="utf-8")


def _clear_pidfile() -> None:
    _pidfile_path().unlink(missing_ok=True)


class _Handler(BaseHTTPRequestHandler):
    # Do not leak the Python/server version to unauthenticated callers.
    server_version = "broker"
    sys_version = ""

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = _InputReader(DeadlineReader(self.connection,
            time.monotonic() + INPUT_TOTAL_SECONDS, INPUT_IDLE_SECONDS))

    def handle_one_request(self):
        # Same serial BaseHTTPRequestHandler flow, but bounded reads and JSON
        # errors on timeouts/framing failures, including before headers exist.
        self.close_connection = True
        self.request_version = "HTTP/1.0"
        self.requestline = ""
        self.command = None
        self._response_started = False
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.send_error(414)
                return
            if not self.raw_requestline or not self.parse_request():
                return
            self.close_connection = True  # no pipelining/reused input budget
            method = getattr(self, "do_" + self.command, None)
            if method is None:
                self.send_error(501)
                return
            method()
            self.wfile.flush()
        except TimeoutError:
            if self._response_started:
                self._output_failed()
            else:
                self.send_error(408)
        except _HeaderTooLarge:
            self.send_error(431)
        except (ConnectionError, OSError):
            if self._response_started:
                self._output_failed()
            # peer disappeared; never retry the action

    def _output_failed(self):
        self.close_connection = True
        try:
            self._ctx().audit.record("gateway", "output_error", "failed",
                                     self._response_correlation_id,
                                     details={"status": self._response_status})
        except Exception:
            pass

    def _output_timeout(self):
        remaining = self._output_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.connection.settimeout(min(OUTPUT_WRITE_SECONDS, remaining))

    def _send_json(self, status, payload, correlation_id):
        self._response_status = status
        self._response_correlation_id = correlation_id
        self._output_deadline = time.monotonic() + OUTPUT_TOTAL_SECONDS
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Correlation-Id", correlation_id)
        self.send_header("Connection", "close")
        # sendall may commit any prefix before failing, even in end_headers.
        # From here onward, failure is output failure, never a new HTTP reply.
        self._response_started = True
        self._output_timeout()
        self.end_headers()
        self._output_timeout()
        self.wfile.write(payload)

    def send_error(self, code, message=None, explain=None):
        # Do not reflect parser exceptions, malformed request lines or values.
        names = {408: "request_timeout", 413: "body_too_large", 500: "internal_error"}
        payload = json.dumps({"error": names.get(code, "invalid_request")}).encode()
        correlation_id = uuid.uuid4().hex
        self.close_connection = True
        try:
            self._ctx().audit.record("gateway", "transport_error", "failed" if code >= 500 else "invalid",
                                     correlation_id, details={"status": code})
        except Exception:
            pass  # unavailable audit storage must not turn refusal into execution
        try:
            self._send_json(code, payload, correlation_id)
        except (OSError, TimeoutError):
            self._output_failed()

    def _ctx(self) -> BrokerContext:
        return self.server.ctx  # type: ignore[attr-defined]

    def _body_cap(self) -> int:
        if self.path.startswith("/v1/actions/"):
            try:
                rest_max = int(os.environ.get("TOOLSTACK_REST_BODY_MAX", str(DEFAULT_REST_BODY_MAX)))
            except ValueError:
                rest_max = DEFAULT_REST_BODY_MAX
            return (max(0, min(rest_max, DEFAULT_REST_BODY_MAX)) * 4 // 3) + (64 * 1024)
        return MAX_BODY_BYTES

    def _read_body(self):
        """Return the parsed JSON body: {} when absent, None on malformed JSON
        (the gateway maps a non-dict body to 400)."""
        lengths = self.headers.get_all("Content-Length", [])
        if len(self.headers.get_all("Idempotency-Key", [])) > 1:
            raise ValueError("duplicate idempotency key")
        if self.headers.get_all("Transfer-Encoding") or len(lengths) > 1:
            raise ValueError("invalid framing")
        value = lengths[0] if lengths else "0"
        if not re.fullmatch(r"[0-9]{1,10}", value):
            raise ValueError("invalid framing")
        length = int(value)
        if length <= 0:
            return {}
        cap = self._body_cap()
        if length > cap:
            return _TooLarge(cap)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("incomplete body")
        try:
            return json.loads(raw)
        except RecursionError:
            raise ValueError("invalid framing") from None
        except (ValueError, UnicodeError):
            return None

    def _respond(self) -> None:
        try:
            body = self._read_body()
        except ValueError:
            self.send_error(400)
            return
        if isinstance(body, _TooLarge):
            correlation_id = uuid.uuid4().hex
            try:
                self._ctx().audit.record("gateway", "transport_error", "invalid", correlation_id,
                                         details={"status": 413})
            except Exception:
                pass
            payload = json.dumps({"error": "body_too_large", "limit_bytes": body.limit}).encode("utf-8")
            self._send_json(413, payload, correlation_id)
            return
        try:
            response = handle(self.command, self.path, dict(self.headers), body, self._ctx())
        except Exception:
            self.send_error(500)
            return
        payload = json.dumps(response.body).encode("utf-8")
        self._send_json(response.status, payload, response.correlation_id)

    # Every method goes through the same fail-closed gateway.
    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond
    do_PATCH = _respond

    def log_message(self, *args) -> None:
        # The audit log is our record of requests; suppress the default access log.
        pass


class _TooLarge:
    def __init__(self, limit: int) -> None:
        self.limit = limit


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
    # Single-threaded HTTPServer: the broker serves one request at a time. That is intentional
    # for 1.0; it keeps the SQLite store, rate limiter, and audit trail free of cross-request
    # races without locking, and the workload (one operator's agents, human-gated approvals) is
    # low-QPS. The cost is that a slow tool forward blocks the next request for up to the
    # per-call timeout (TOOLSTACK_TOOL_TIMEOUT; see broker/runtime.py). Revisit with a
    # ThreadingHTTPServer + per-connection store handles if real concurrency is ever needed.
    server = HTTPServer((bind_host, bind_port), _Handler)
    server.ctx = ctx  # type: ignore[attr-defined]
    server.tools_root = tools_root  # type: ignore[attr-defined]
    server.tool_dirs = tuple(tool_dirs or ())  # type: ignore[attr-defined]
    server.reload_registry = lambda: _reload_registry(server)  # type: ignore[attr-defined]
    _publish_catalog_receipt(server)
    return server


def _catalog_counts(registry: Registry) -> tuple[int, int]:
    catalog = getattr(registry, "_catalog", {})
    return len(catalog), len(registry.list_ops())


def _publish_catalog_receipt(server) -> None:
    observation = uuid.uuid4().hex
    server.ctx.store.set_catalog_receipt({
        "observation_id": observation,
        "fingerprint": server.ctx.registry.observation_fingerprint(server.tools_root, server.tool_dirs),
    })
    server.ctx.catalog_observation_id = observation


def _reload_registry(server) -> Registry:
    # Invalidate before parsing: failed reload must not certify the previous catalog.
    server.ctx.catalog_observation_id = None
    server.ctx.store.set_catalog_receipt(None)
    old = server.ctx.registry
    before_tools, before_ops = _catalog_counts(old)
    new = Registry.from_sources(server.tools_root, server.tool_dirs)
    server.ctx.registry = new
    _publish_catalog_receipt(server)
    after_tools, after_ops = _catalog_counts(new)
    server.ctx.audit.record(
        "registry", "reloaded", "ok", uuid.uuid4().hex,
        details={
            "tools_before": before_tools,
            "ops_before": before_ops,
            "tools_after": after_tools,
            "ops_after": after_ops,
        },
    )
    return new


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
    _write_pidfile()

    def _sighup(_signum, _frame):
        try:
            server.reload_registry()  # type: ignore[attr-defined]
        except Exception:
            logging.exception("registry reload failed")

    signal.signal(signal.SIGHUP, _sighup)
    host, port = server.server_address
    print(f"broker listening on http://{host}:{port}  (health: GET /v1/health)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.ctx.store.close()  # type: ignore[attr-defined]
        _clear_pidfile()


if __name__ == "__main__":
    main()
