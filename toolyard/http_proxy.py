"""A generic outbound REST proxy, used as a tool entrypoint, so an external HTTP API
becomes a Toolstack ``rest`` tool by configuration alone, with no tool code to write.

Point a tool's ``[entrypoint] command`` at ``python3 -m toolyard.http_proxy`` and add a
``[proxy]`` block to its ``toolyard.toml`` (the broker and toolyard ignore that block; only
this program reads it):

    id = "graph"
    type = "rest"
    [entrypoint]
    command = "python3 -m toolyard.http_proxy"
    port = 4640
    [proxy]
    base_url = "https://graph.microsoft.com/v1.0"
    inject = [
        { into = "header", name = "Authorization", value = "Bearer ${secret:graph_token}" },
    ]
    [[operations]]            # the verbs you allow; policy scopes them per (verb, path)
    name = "GET"
    [[secrets]]
    name = "graph_token"
    field = "GRAPH_TOKEN"     # resolved from your backend into THIS process, never the broker

The broker forwards ``<verb> 127.0.0.1:<port><path>`` here (the verb-as-op rest passthrough);
this process injects the declared secrets and forwards to ``base_url`` + path. Security spine:

  - **Secrets stay off the broker.** The toolyard resolves them into this workload's secrets
    dir; the broker only ever talks to loopback and never sees them. They go out in the
    upstream request and are never returned, logged, or echoed to the caller.
  - **base_url pinning (no SSRF).** Every request is pinned to ``base_url``'s scheme+host, and
    the caller's path is normalised and must stay under ``base_url``'s path prefix, so ``..``,
    a host swap, or a protocol-relative target can't redirect it elsewhere. A ``${secret:...}``
    ref may appear in base_url's PATH (e.g. a secret account id in the prefix), never the host.
  - **The injected auth is not caller-overridable.** Caller headers are NOT forwarded upstream by
    default; only the configured injections (plus Content-Type for a JSON body) go out. An
    operator can allowlist specific app headers with ``forward_headers`` (e.g. ``If-Match``,
    ``Prefer``); the auth and broker headers can never be on that list, so the credential wins.
  - **Defense in depth.** Like the other templates, if a ``broker_secret`` is provisioned this
    process requires the broker's ``X-Toolstack-Secret`` header, so a stray loopback process
    can't use the proxy (and its injected credentials) to reach the API behind the broker's
    back. STRONGLY recommended for a proxy: it is the one tool that holds live API credentials.

Optional secret rotation (provider-agnostic). When a token expires, whoever re-auth'd (the bot,
out of band, by whatever scheme the API uses) can store the fresh token in place so the next
call uses it, without anyone seeing the backend:

    [proxy]
    rotatable = ["graph_token"]          # writable secrets the control plane may set
    [[secrets]]
    name = "graph_token"
    writable = true                      # so the toolyard spawns the write-proxy

    PUT /.toolstack/secret/graph_token  {"value": "<fresh token>"}  ->  {"ok": true, "rotated": "graph_token"}

The proxy re-reads the secret per request, so the new value takes effect immediately; it never
holds the backend itself, only forwarding to the toolyard's write-proxy. The op is off unless
``rotatable`` is non-empty, the broker still policy-gates PUT on the control path, and the write
itself never echoes the value. No OAuth assumption: the proxy stores whatever token it's handed.

Stdlib only.
"""

from __future__ import annotations

import hmac
import json
import os
import posixpath
import re
import socket
import tomllib
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

SECRETS_DIR = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")
PORT = int(os.environ.get("TOOLSTACK_PORT", "0"))
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")
CONFIG_PATH = os.environ.get("TOOLSTACK_PROXY_CONFIG", "toolyard.toml")
TIMEOUT = float(os.environ.get("TOOLSTACK_PROXY_TIMEOUT", "30"))
# The control-plane write hop is to a local Unix socket, which should answer near-instantly; bound
# it tighter than the upstream timeout so a wedged write-proxy can't stall this tool for 30s.
_WRITE_PROXY_TIMEOUT = float(os.environ.get("TOOLSTACK_PROXY_WRITE_TIMEOUT", "5"))
_MAX_BODY = 10 * 1024 * 1024   # cap the request body so a huge Content-Length can't exhaust memory
_MAX_SECRET_VALUE = 64 * 1024  # a token is small; refuse a junk-sized rotation write

_VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
# Reserved path for the opt-in secret-rotation control plane (PUT <prefix>/<name> {value}). A
# request here is handled locally and never forwarded upstream; override per tool if it collides.
_DEFAULT_CONTROL_PREFIX = "/.toolstack/secret"
# A secret name is an operator-chosen field; bound it to a single path component (no separators,
# no `..`) so a `${secret:..}` ref can never read outside the secrets dir.
_SECRET_REF = re.compile(r"\$\{secret:([A-Za-z0-9_-]+)\}")
_SECRET_NAME = re.compile(r"\A[A-Za-z0-9_-]+\Z")   # the charset a rotatable name must match
_HEADER_NAME = re.compile(r"\A[A-Za-z0-9!#$%&'*+.^_`|~-]+\Z")   # RFC 7230 header-name token chars
# Caller headers the proxy refuses to forward even if an operator allowlists them: the injected
# auth must always win, and these are transport-, framing-, or broker-owned (forwarding them
# would invite request smuggling, body/Content-Type desync, or auth confusion at the upstream).
_NEVER_FORWARD = {
    "authorization", "host", "content-length", "content-type", "connection", "transfer-encoding",
    "te", "trailer", "expect", "upgrade", "cookie", "x-toolstack-secret",
}
_NEVER_FORWARD_PREFIXES = ("x-toolstack-", "proxy-", "x-forwarded-")
# Percent-encoded path separators / dot-segments: normpath can't see them, so reject them before
# they reach an upstream that might decode them past our base-prefix check.
_ENCODED_SEP = re.compile(r"%2[ef]|%5c", re.IGNORECASE)


def _read_secret(name: str) -> str:
    with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as fh:
        return fh.read().strip()


def resolve_value(template: str, read_secret=_read_secret) -> str:
    """Substitute ``${secret:NAME}`` refs in an inject value with the secret's content. The
    NAME is operator config (never caller input) and is bounded to one path component."""
    return _SECRET_REF.sub(lambda m: read_secret(m.group(1)), template)


def build_upstream(base_url: str, caller_path: str, caller_query: str) -> str:
    """Pin the request under ``base_url``: same scheme+host, and the caller's path normalised so
    it stays under ``base_url``'s path prefix. Returns the final URL; raises ValueError on any
    escape attempt (host swap, ``..`` past the prefix, protocol-relative authority)."""
    base = urlsplit(base_url)
    if not caller_path.startswith("/") or caller_path.startswith("//"):
        raise ValueError(f"path must start with a single '/': {caller_path!r}")
    if _ENCODED_SEP.search(caller_path):
        raise ValueError("path may not contain percent-encoded '.' or '/' (%2e/%2f/%5c)")
    base_path = base.path.rstrip("/")
    joined = posixpath.normpath(base_path + "/" + caller_path.lstrip("/"))
    # normpath can collapse `..`; if a prefix is configured, the result must stay under it.
    if base_path and joined != base_path and not joined.startswith(base_path + "/"):
        # echo only the caller's own path, not base_path (the upstream URL's prefix)
        raise ValueError(f"path escapes the configured base prefix: {caller_path!r}")
    final = urlunsplit((base.scheme, base.netloc, joined, caller_query, ""))
    chk = urlsplit(final)
    if (chk.scheme, chk.netloc) != (base.scheme, base.netloc):  # backstop: never leave the origin
        raise ValueError("upstream host escape")   # no URL in the message (it can carry the secret)
    return final


def apply_injections(inject: list, read_secret=_read_secret):
    """Split the configured injections into (headers, query-pairs, body-fields), resolving
    ``${secret:...}`` refs. ``inject`` is a list of ``{into, name, value}`` from the config."""
    headers: dict[str, str] = {}
    query: list[tuple[str, str]] = []
    body: dict = {}
    for entry in inject or []:
        into, name = entry.get("into"), entry.get("name")
        value = resolve_value(str(entry.get("value", "")), read_secret)
        if into == "header":
            headers[name] = value
        elif into == "query":
            query.append((name, value))
        elif into == "body":
            body[name] = value
        else:
            raise SystemExit(f"http_proxy: inject 'into' must be header/query/body, got {into!r}")
    return headers, query, body


def write_secret_via_proxy(name: str, value: str, timeout: float = TIMEOUT) -> tuple[int, dict]:
    """Write a writable secret back through the toolyard's write-proxy (the local Unix socket at
    ``$TOOLYARD_SECRETS_SOCKET``). The write-proxy holds the backend and re-checks that the secret
    is declared ``writable``, so this process never touches the backend credential directly. Used
    by the rotation control plane so a bot can store a re-auth'd token without anyone seeing the
    backend. Returns ``(status, parsed_body)``; raises OSError/RuntimeError on a transport problem."""
    sock_path = os.environ.get("TOOLYARD_SECRETS_SOCKET")
    if not sock_path:
        raise RuntimeError("no write-proxy socket; declare the secret writable = true")
    payload = json.dumps({"value": value}).encode("utf-8")
    safe_name = quote(name, safe="")   # never let a name reach the request line raw (defense in depth)
    request = (f"POST /v1/secrets/{safe_name} HTTP/1.1\r\nHost: toolyard\r\n"
               f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n").encode("ascii") + payload
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(sock_path)
        conn.sendall(request)
        chunks = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        conn.close()
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    fields = head.split(b" ", 2)
    status = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
    try:
        return status, json.loads(body or b"{}")
    except json.JSONDecodeError:
        return status, {}


def load_proxy_config(path: str = CONFIG_PATH) -> dict:
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    proxy = data.get("proxy")
    if not isinstance(proxy, dict) or not proxy.get("base_url"):
        raise SystemExit("http_proxy: the tool's toolyard.toml needs a [proxy] block with base_url")
    base = urlsplit(proxy["base_url"])
    if base.scheme not in ("http", "https") or not base.netloc:
        raise SystemExit(f"http_proxy: base_url must be an absolute http(s) URL, got {proxy['base_url']!r}")
    if _SECRET_REF.search(base.scheme) or _SECRET_REF.search(base.netloc):
        # secrets may fill a path segment (e.g. an account id in the prefix), never the host:
        # the host stays fixed so every request is pinned to one origin.
        raise SystemExit("http_proxy: base_url ${secret:...} refs are allowed only in the path, not the host")
    fwd = proxy.get("forward_headers", [])
    if not isinstance(fwd, list) or not all(isinstance(s, str) for s in fwd):
        raise SystemExit("http_proxy: [proxy] forward_headers must be a list of header names")
    for h in fwd:
        if not _HEADER_NAME.match(h):
            raise SystemExit(f"http_proxy: [proxy] forward_headers has an invalid header name {h!r}")
        if h.lower() in _NEVER_FORWARD or h.lower().startswith(_NEVER_FORWARD_PREFIXES):
            raise SystemExit(f"http_proxy: [proxy] forward_headers may not include the reserved header {h!r}")
    rotatable = proxy.get("rotatable", [])
    if not isinstance(rotatable, list) or not all(isinstance(s, str) for s in rotatable):
        raise SystemExit("http_proxy: [proxy] rotatable must be a list of writable secret names")
    if not all(_SECRET_NAME.match(s) for s in rotatable):
        raise SystemExit("http_proxy: [proxy] rotatable names must match [A-Za-z0-9_-]+")
    cp = proxy.get("control_prefix", _DEFAULT_CONTROL_PREFIX)
    if not isinstance(cp, str) or not cp.startswith("/"):
        raise SystemExit("http_proxy: [proxy] control_prefix must be an absolute path")
    return proxy


def _verify_broker(headers) -> bool:
    """Opt-in: if a ``broker_secret`` is provisioned, require the broker's ``X-Toolstack-Secret``
    to match (constant-time). No secret file => the check is off (mirrors the broker sending no
    header). For a proxy this is what stops a stray loopback caller from using the injected
    credentials directly, bypassing the broker's policy."""
    try:
        expected = _read_secret("broker_secret")
    except FileNotFoundError:
        return True
    if not expected:
        return True
    presented = headers.get("X-Toolstack-Secret", "")
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _handler(proxy: dict):
    base_url = proxy["base_url"]
    _base = urlsplit(base_url)
    base_netloc = _base.netloc                       # fixed host; a base_url secret may fill the path only
    base_has_path = bool(_base.path.rstrip("/"))
    base_has_secret = bool(_SECRET_REF.search(base_url))
    inject = proxy.get("inject", [])
    forward_headers = proxy.get("forward_headers", [])   # caller headers the operator lets through
    rotatable = set(proxy.get("rotatable", []))   # writable secrets the control plane may set
    control_prefix = proxy.get("control_prefix", _DEFAULT_CONTROL_PREFIX)

    class Handler(BaseHTTPRequestHandler):
        server_version = "toolstack-proxy"
        sys_version = ""
        timeout = TIMEOUT   # bound a slow/dribbling request read (the server is single-threaded)

        def _proxy(self) -> None:
            try:
                self._forward()
            except Exception as exc:  # never leak a stack trace or a secret to the caller
                self._reply(500, {"error": "proxy_error", "detail": type(exc).__name__})

        def _forward(self) -> None:
            if not _verify_broker(self.headers):
                return self._reply(401, {"error": "unauthorized"})
            verb = self.command.upper()
            if verb not in _VERBS:
                return self._reply(405, {"error": "method_not_allowed"})
            split = urlsplit(self.path)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._reply(400, {"error": "invalid_content_length"})
            if length < 0 or length > _MAX_BODY:
                return self._reply(413, {"error": "body_too_large"})
            raw = self.rfile.read(length) if length else b""

            # Opt-in rotation control plane (PUT <control_prefix>/<name> {value}): write a writable
            # secret back through the toolyard's write-proxy. Handled locally, never forwarded
            # upstream, so a bot that re-auth'd out of band can store the fresh token in place.
            if rotatable and (split.path == control_prefix or split.path.startswith(control_prefix + "/")):
                return self._rotate(verb, split.path, raw)

            try:
                body = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return self._reply(400, {"error": "invalid_json_body"})

            try:
                resolved_base = resolve_value(base_url)   # fill any ${secret:...} in the base path
                inj_headers, inj_query, inj_body = apply_injections(inject)
            except FileNotFoundError:  # a referenced secret isn't provisioned (don't echo the path)
                return self._reply(503, {"error": "secret_unavailable"})
            if base_has_secret:
                # A path secret must not move the host, introduce a query/fragment, or (if
                # misprovisioned empty) collapse the confining prefix to root; each would widen
                # the request's scope, so fail closed rather than open.
                rb = urlsplit(resolved_base)
                if (rb.netloc != base_netloc or rb.query or rb.fragment
                        or (base_has_path and not rb.path.rstrip("/"))):
                    return self._reply(503, {"error": "secret_unavailable"})
            query = urlencode(parse_qsl(split.query, keep_blank_values=True) + inj_query)
            try:
                url = build_upstream(resolved_base, split.path, query)
            except ValueError as exc:
                return self._reply(400, {"error": "bad_path", "detail": str(exc)})

            # By default only the configured injections go upstream; the caller's own headers are
            # NOT forwarded (they could otherwise override the injected auth or smuggle headers). An
            # operator can opt specific app headers through with [proxy] forward_headers; the auth
            # and broker/transport headers can never be on that list, so override-protection holds.
            headers = dict(inj_headers)
            injected = {k.lower() for k in headers}
            for name in forward_headers:
                lname = name.lower()
                if lname in _NEVER_FORWARD or lname.startswith(_NEVER_FORWARD_PREFIXES) or lname in injected:
                    continue
                value = self.headers.get(name)
                if value is None:
                    continue
                if any(not (0x20 <= ord(c) <= 0x7e) for c in value):
                    # printable ASCII only: a CRLF (or obs-fold "CRLF + space", which urllib
                    # permits) in the value would smuggle a header line into the upstream request.
                    return self._reply(400, {"error": "bad_forward_header"})
                headers[name] = value
            if inj_body:
                if body is not None and not isinstance(body, dict):
                    return self._reply(400, {"error": "body_must_be_object"})
                body = {**(body or {}), **inj_body}
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")

            req = urllib.request.Request(url, data=data, headers=headers, method=verb)
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    status, payload, ctype = resp.status, resp.read(), resp.headers.get("Content-Type", "")
            except urllib.error.HTTPError as exc:  # a 4xx/5xx is a real REST answer, pass it through
                status, payload, ctype = exc.code, exc.read(), exc.headers.get("Content-Type", "")
                exc.close()
            except urllib.error.URLError as exc:
                return self._reply(502, {"error": "upstream_unreachable", "detail": str(exc.reason)})
            self._reply_raw(status, payload, ctype or "application/json")

        def _rotate(self, verb: str, path: str, raw: bytes) -> None:
            """Store a writable secret on behalf of the caller. Gated four ways: the op only
            exists when ``rotatable`` is non-empty; the broker still policy-gates PUT on the
            control path; the name must be in ``rotatable``; and the write-proxy independently
            re-checks the secret is ``writable``. The value is never echoed back."""
            if verb != "PUT":
                return self._reply(405, {"error": "method_not_allowed"})
            name = path[len(control_prefix):].lstrip("/")
            if name not in rotatable:
                return self._reply(403, {"error": "secret_not_rotatable"})
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self._reply(400, {"error": "invalid_json_body"})
            value = payload.get("value") if isinstance(payload, dict) else None
            if not isinstance(value, str) or not value:
                return self._reply(400, {"error": "value_must_be_a_nonempty_string"})
            if len(value.encode("utf-8")) > _MAX_SECRET_VALUE:
                return self._reply(413, {"error": "value_too_large"})
            try:
                status, _ = write_secret_via_proxy(name, value, timeout=_WRITE_PROXY_TIMEOUT)
            except (OSError, RuntimeError):  # socket missing/unreachable (don't echo the path)
                return self._reply(503, {"error": "secret_write_unavailable"})
            if status != 200:
                # Don't echo the write-proxy's raw failure: it can carry a backend path or API
                # detail. The operator sees the real reason in the write-proxy's own log.
                return self._reply(502, {"error": "secret_write_failed"})
            self._reply(200, {"ok": True, "rotated": name})   # never echo the value back

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _proxy

        def _reply(self, status: int, obj: dict) -> None:
            self._reply_raw(status, json.dumps(obj).encode("utf-8"), "application/json")

        def _reply_raw(self, status: int, payload: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args) -> None:  # quiet; the broker audits the call
            pass

    return Handler


def main() -> None:
    proxy = load_proxy_config()
    server = HTTPServer((BIND, PORT), _handler(proxy))
    server.serve_forever()


if __name__ == "__main__":
    main()
