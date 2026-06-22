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
    a host swap, or a protocol-relative target can't redirect it elsewhere.
  - **The injected auth is not caller-overridable.** Caller-supplied headers are NOT forwarded
    upstream; only the configured injections (plus Content-Type for a JSON body) go out.
  - **Defense in depth.** Like the other templates, if a ``broker_secret`` is provisioned this
    process requires the broker's ``X-Toolstack-Secret`` header, so a stray loopback process
    can't use the proxy (and its injected credentials) to reach the API behind the broker's
    back. STRONGLY recommended for a proxy: it is the one tool that holds live API credentials.

Stdlib only.
"""

from __future__ import annotations

import hmac
import json
import os
import posixpath
import re
import tomllib
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRETS_DIR = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")
PORT = int(os.environ.get("TOOLSTACK_PORT", "0"))
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")
CONFIG_PATH = os.environ.get("TOOLSTACK_PROXY_CONFIG", "toolyard.toml")
TIMEOUT = float(os.environ.get("TOOLSTACK_PROXY_TIMEOUT", "30"))
_MAX_BODY = 10 * 1024 * 1024   # cap the request body so a huge Content-Length can't exhaust memory

_VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
# A secret name is an operator-chosen field; bound it to a single path component (no separators,
# no `..`) so a `${secret:..}` ref can never read outside the secrets dir.
_SECRET_REF = re.compile(r"\$\{secret:([A-Za-z0-9_-]+)\}")
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
        raise ValueError(f"path escapes base_url prefix {base_path!r}: {caller_path!r}")
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


def load_proxy_config(path: str = CONFIG_PATH) -> dict:
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    proxy = data.get("proxy")
    if not isinstance(proxy, dict) or not proxy.get("base_url"):
        raise SystemExit("http_proxy: the tool's toolyard.toml needs a [proxy] block with base_url")
    base = urlsplit(proxy["base_url"])
    if base.scheme not in ("http", "https") or not base.netloc:
        raise SystemExit(f"http_proxy: base_url must be an absolute http(s) URL, got {proxy['base_url']!r}")
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
    inject = proxy.get("inject", [])

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
            try:
                body = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return self._reply(400, {"error": "invalid_json_body"})

            try:
                inj_headers, inj_query, inj_body = apply_injections(inject)
            except FileNotFoundError:  # a referenced secret isn't provisioned (don't echo the path)
                return self._reply(503, {"error": "secret_unavailable"})
            query = urlencode(parse_qsl(split.query, keep_blank_values=True) + inj_query)
            try:
                url = build_upstream(base_url, split.path, query)
            except ValueError as exc:
                return self._reply(400, {"error": "bad_path", "detail": str(exc)})

            # Only the configured injections go upstream; the caller's own headers are NOT
            # forwarded (they could otherwise override the injected auth or smuggle headers).
            headers = dict(inj_headers)
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
