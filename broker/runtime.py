"""Tool runtime (the execution seam): forward an approved call to the tool
container on ``127.0.0.1:<port>``.

Three tool transports share this seam, dispatched on ``ToolOp.type``:

* **api**: the broker POSTs ``/v1/actions/<op>`` with the arguments + broker
  context and returns the tool's JSON (the original toolyard contract).
* **mcp**: the tool is a **streamable-HTTP MCP server** listening at
  ``127.0.0.1:<port>/mcp``. The broker is the MCP *client*: it runs the
  ``initialize`` handshake, then issues ``tools/call`` with ``name = <op>``.
  The op is still the unit of policy/approval, so an mcp tool declares its ops
  in ``toolyard.toml`` exactly like an api tool; the runtime maps op -> MCP tool
  name. The MCP ``result`` (content blocks + optional ``structuredContent``) is
  returned to the caller unchanged.
* **rest**: a **verb-as-op passthrough**: the op IS an HTTP verb (GET/POST/PUT/
  PATCH/DELETE). The caller passes ``{path, body, query, headers}``; the broker forwards
  the raw ``<verb> 127.0.0.1:<port><path>`` request, caller headers included, minus the
  broker-reserved namespace (see ``_RESERVED_REQ_HEADERS``), and returns the tool's
  ``{status, headers, body}``. Policy/approval still key on ``(tool, <verb>)``. A 4xx/5xx
  from the tool is a legitimate REST response and passes through as data; only a
  transport failure raises. The path is validated to stay on the tool's loopback
  origin (no scheme/host injection).

The broker attaches NO workload secrets; the tool already has its own, resolved
by the toolyard at container start. The broker adds ``broker_request_id`` and the
caller name so the tool has request context (in the api body; in MCP under the
call's ``_meta``).

As optional defense in depth, the broker may present a per-tool **shared secret**
(the ``X-Toolstack-Secret`` header) so the tool can prove the call came from the
broker, not from another loopback process that merely guessed the tool's port and
called it directly, bypassing policy and approval. The secret is the broker's own
*channel* credential for this hop; it is NOT a workload secret (the broker still
never reads the secret backend). It is opt-in per tool: with none configured the
header is absent and the tool-side check stays off, so existing tools are
unaffected. The same header rides every MCP request. See ``_env_tool_secret`` and
``docs/message-contracts.md``.

Unreachable or non-2xx tools, and JSON-RPC protocol errors, raise, which the
request lifecycle maps to 502. (A *handled* tool error rides back in-band: a 2xx
body for an api tool, an ``isError`` result for an mcp tool; neither raises, both
reach the caller, mirroring the api path's "tool returns 200 + error body".)
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from .registry import ToolOp

# Protocol version the broker advertises in `initialize`. A streamable-HTTP MCP
# server negotiates down if it speaks an older one; we send a recent dated version.
MCP_PROTOCOL_VERSION = "2025-06-18"

# The HTTP verbs a "rest" passthrough tool may expose as ops. The op IS the verb, so this
# also guards against using an arbitrary op string as an HTTP method (method injection).
REST_VERBS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# Request headers the broker OWNS on a rest passthrough: a caller can't set or override
# these. The X-Toolstack-* namespace carries the broker's caller-identity assertion + the
# opt-in shared secret (forwarding a caller's copy would let an agent impersonate another
# caller); Host/Content-Length are computed for the loopback hop; Content-Type matches the
# broker's JSON body; the hop-by-hop headers are per-connection. Everything ELSE the caller
# puts in `arguments.headers` is forwarded, so the passthrough is faithful for app headers
# (Accept, an upstream Authorization, custom X-* ...) without ceding the broker's identity.
_RESERVED_REQ_HEADERS = frozenset({
    "host", "content-length", "content-type",
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*\Z")  # \Z (not $) so a trailing \n can't slip in


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow a tool-issued redirect. The response (including its Location) is
    controlled by the tool, so following a 3xx would let the tool steer the broker to an
    arbitrary host, an un-mediated request the broker would never have approved (SSRF). A
    3xx instead surfaces as an HTTPError: the api/mcp paths treat it as a tool error; the
    rest passthrough returns it to the caller as data."""

    def redirect_request(self, *args, **kwargs):
        return None


# One opener for every tool hop, with redirect-following disabled. Built once; openers are
# thread-safe for concurrent .open() calls.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _env_tool_secret(tool_id: str) -> str | None:
    """The shared secret the broker presents to ``tool_id``, read from the env var
    ``TOOLSTACK_TOOL_SECRET_<TOOL>`` (id upper-cased, runs of non-alphanumerics collapsed
    to a single ``_`` so e.g. ``apple-calendar`` -> ``TOOLSTACK_TOOL_SECRET_APPLE_CALENDAR``).

    Returns None when unset or empty (after stripping); the feature is opt-in, so an
    unconfigured tool gets no header. The value is **stripped of surrounding whitespace**
    so it matches the tool side, which reads its copy through the same strip (a stray
    trailing newline in the env must not silently 401 every call).

    The operator provisions the SAME value in two places: this env var (so the broker
    sends it) and the tool's secret backend (so the toolyard injects it for the tool to
    verify against). Note the id->env mapping is not injective: ids that differ only in
    case or in non-alphanumeric runs (``apple-calendar`` vs ``apple.calendar``) collapse to
    the same env var; keep tool ids distinct under this normalization. A collision only
    means the two tools share one channel secret, never that calls cross-wire (each tool
    still listens on its own loopback port)."""
    key = "TOOLSTACK_TOOL_SECRET_" + re.sub(r"[^A-Z0-9]+", "_", tool_id.upper())
    return (os.environ.get(key) or "").strip() or None


class HttpRuntime:
    """Forwards an approved call over HTTP. Handles all three tool transports (api,
    streamable-HTTP mcp, rest passthrough); the constructor and ``execute`` signature are
    shared, dispatched on ``ToolOp.type``."""

    def __init__(self, timeout: float | None = None, tool_secret=_env_tool_secret) -> None:
        # Per-call cap on a tool forward (default 30s, override TOOLSTACK_TOOL_TIMEOUT). The
        # broker serves requests serially (single-threaded HTTPServer, see broker/server.py),
        # so one slow tool ties up the whole broker for this window; tune it down for a fleet of
        # fast tools, or up for a deliberately slow one.
        if timeout is None:
            try:
                timeout = float(os.environ.get("TOOLSTACK_TOOL_TIMEOUT", "30"))
            except ValueError:
                timeout = 30.0
        self._timeout = timeout
        self._tool_secret = tool_secret

    def execute(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        if tool_op.type == "api":
            return self._execute_api(tool_op, arguments, request_id, caller_name)
        if tool_op.type == "mcp":
            return self._execute_mcp(tool_op, arguments, request_id, caller_name)
        if tool_op.type == "rest":
            return self._execute_rest(tool_op, arguments, request_id, caller_name)
        # The registry rejects unknown types at load, so this guards only a programmer error
        # (a ToolOp built with a type no transport handles), fail loud, never POST blind.
        raise RuntimeError(f"unsupported tool type {tool_op.type!r}")

    # -- api transport: POST /v1/actions/<op> ------------------------------------
    def _execute_api(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        url = f"http://127.0.0.1:{tool_op.port}/v1/actions/{tool_op.op}"
        payload = json.dumps(
            {
                "arguments": arguments,
                "broker_request_id": request_id,
                "caller": {"name": caller_name},
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        secret = self._tool_secret(tool_op.tool)
        if secret:
            headers["X-Toolstack-Secret"] = secret
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with _OPENER.open(req, timeout=self._timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"tool returned HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"tool unreachable: {exc.reason}")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError("tool returned non-JSON")

    # -- mcp transport: streamable-HTTP MCP client at /mcp -----------------------
    def _execute_mcp(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        base = f"http://127.0.0.1:{tool_op.port}/mcp"
        secret = self._tool_secret(tool_op.tool)
        # 1. initialize: negotiate the protocol version and capture the session id the server
        #    may pin the exchange to. No protocol header here: it isn't negotiated yet.
        init_result, session = self._mcp_request(
            base, secret, None, None, 1, "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "toolstack-broker", "version": "0.1.0"},
            },
        )
        if not isinstance(init_result, dict):
            raise RuntimeError("tool did not return an MCP initialize result")
        # The streamable-HTTP transport wants every post-initialize request to carry the
        # version the server negotiated (it may pick a different one than we advertised); use
        # our advertised version only if the server returned none.
        protocol = init_result.get("protocolVersion") or MCP_PROTOCOL_VERSION
        # 2. notifications/initialized: a fire-and-forget notification (no response).
        self._mcp_notify(base, secret, session, protocol, "notifications/initialized", {})
        # 3. tools/call: op IS the MCP tool name; broker context rides in _meta.
        result, _ = self._mcp_request(
            base, secret, session, protocol, 2, "tools/call",
            {
                "name": tool_op.op,
                "arguments": arguments,
                "_meta": {"broker_request_id": request_id, "caller": {"name": caller_name}},
            },
        )
        if result is None:
            raise RuntimeError("tool returned no MCP result")
        return result

    def _mcp_request(self, base, secret, session, protocol, msg_id, method, params):
        """One JSON-RPC request/response over streamable HTTP. Returns
        ``(result, session_id)``; raises on transport, non-2xx, or a JSON-RPC error."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if secret:
            headers["X-Toolstack-Secret"] = secret
        if session:
            headers["Mcp-Session-Id"] = session
        if protocol:
            headers["MCP-Protocol-Version"] = protocol
        body = json.dumps(
            {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
        ).encode("utf-8")
        req = urllib.request.Request(base, data=body, headers=headers, method="POST")
        try:
            with _OPENER.open(req, timeout=self._timeout) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                new_session = resp.headers.get("Mcp-Session-Id")
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"tool returned HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"tool unreachable: {exc.reason}")
        message = self._parse_jsonrpc(raw, ctype)
        if "error" in message:
            err = message["error"] or {}
            raise RuntimeError(f"tool MCP error: {err.get('message', err)}")
        return message.get("result"), (new_session or session)

    def _mcp_notify(self, base, secret, session, protocol, method, params):
        """Send a JSON-RPC notification (no id, no response). Best-effort: a
        notification is fire-and-forget by spec, so a missing/empty reply is fine."""
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if secret:
            headers["X-Toolstack-Secret"] = secret
        if session:
            headers["Mcp-Session-Id"] = session
        if protocol:
            headers["MCP-Protocol-Version"] = protocol
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(base, data=body, headers=headers, method="POST")
        try:
            with _OPENER.open(req, timeout=self._timeout) as resp:
                resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass  # notification delivery is not acknowledged; the tools/call below is the real probe

    @staticmethod
    def _parse_jsonrpc(raw: bytes, ctype: str) -> dict:
        """A streamable-HTTP MCP server answers a POST with either a single JSON
        object (``application/json``) or an SSE stream (``text/event-stream``) whose
        ``data:`` event carries the JSON-RPC message. Handle both."""
        if "text/event-stream" in ctype:
            return HttpRuntime._parse_sse(raw.decode("utf-8", "replace"))
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError("tool returned non-JSON")
        if not isinstance(message, dict):
            raise RuntimeError("tool returned a non-object JSON-RPC message")
        return message

    @staticmethod
    def _parse_sse(text: str) -> dict:
        """Pull the first JSON-RPC response out of an SSE stream. Events are blank-line
        separated; an event's ``data:`` lines concatenate (SSE spec). We want the first
        event that decodes to a response (has ``result`` or ``error``)."""
        data_lines: list[str] = []

        def flush():
            if not data_lines:
                return None
            try:
                msg = json.loads("\n".join(data_lines))
            except json.JSONDecodeError:
                return None
            return msg if isinstance(msg, dict) else None

        for line in text.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[len("data:"):].lstrip())
            elif line.strip() == "":
                msg = flush()
                data_lines = []
                if msg is not None and ("result" in msg or "error" in msg):
                    return msg
        msg = flush()  # trailing event with no terminating blank line
        if msg is not None and ("result" in msg or "error" in msg):
            return msg
        raise RuntimeError("tool returned no JSON-RPC response in SSE stream")

    # -- rest transport: verb-as-op passthrough to 127.0.0.1:<port><path> ---------
    def _execute_rest(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        verb = tool_op.op.upper()
        if verb not in REST_VERBS:
            # the registry only registers declared ops, but never use an arbitrary string
            # as an HTTP method; guard against method injection explicitly.
            raise RuntimeError(f"unsupported REST verb {tool_op.op!r}")
        path = self._rest_path(arguments)
        url = f"http://127.0.0.1:{tool_op.port}{path}"
        # Forward the caller's headers (minus the reserved namespace), then layer the broker's
        # OWN headers on top so they always win; the broker's caller-identity assertion can't
        # be spoofed. (The body belongs to the caller's request, unlike the api transport where
        # context shares the JSON body, so context rides in headers here.)
        headers = self._rest_headers(arguments)
        headers["X-Toolstack-Request-Id"] = str(request_id)
        headers["X-Toolstack-Caller"] = caller_name
        body = arguments.get("body")
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        secret = self._tool_secret(tool_op.tool)
        if secret:
            headers["X-Toolstack-Secret"] = secret
        req = urllib.request.Request(url, data=data, headers=headers, method=verb)
        try:
            with _OPENER.open(req, timeout=self._timeout) as resp:
                status, raw, msg = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            # A 4xx/5xx is a legitimate REST response in a passthrough (e.g. a 404 for a
            # missing resource the caller asked about): return it as data, don't raise.
            status, raw, msg = exc.code, exc.read(), exc.headers
            exc.close()
        except urllib.error.URLError as exc:
            raise RuntimeError(f"tool unreachable: {exc.reason}")
        ctype = msg.get("Content-Type", "") if msg else ""
        # Return the tool's response headers too (full passthrough fidelity: Location on a
        # 201, Content-Type, pagination/rate-limit headers). dict() collapses a repeated
        # header to its last value, fine for the single-valued headers a caller acts on.
        resp_headers = dict(msg.items()) if msg else {}
        return {"status": status, "headers": resp_headers, "body": self._parse_body(raw, ctype)}

    @staticmethod
    def _rest_headers(arguments: dict) -> dict:
        """Validate and filter the caller's ``headers`` (an optional name->value object).
        Drops the broker-reserved headers (so the caller can't spoof the broker's identity or
        the channel secret) and rejects malformed names / control-character values (header
        injection). Returns the forwardable subset; the broker adds its own headers after."""
        raw = arguments.get("headers")
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise RuntimeError("rest 'headers' must be an object")
        out: dict = {}
        for name, value in raw.items():
            if not isinstance(name, str) or not _HEADER_NAME_RE.match(name):
                raise RuntimeError(f"invalid rest header name {name!r}")
            if not isinstance(value, str):
                raise RuntimeError(f"rest header {name!r} value must be a string")
            # printable ASCII only: rejects CR/LF/control chars (injection) and non-latin-1
            # (which http.client can't encode); the broker's own validator, not a stdlib backstop.
            if any(not (0x20 <= ord(c) <= 0x7e) for c in value):
                raise RuntimeError(f"rest header {name!r} value has an invalid character")
            lname = name.lower()
            if lname in _RESERVED_REQ_HEADERS or lname.startswith("x-toolstack-"):
                continue  # broker-owned: silently drop a caller attempt to set it
            out[name] = value
        return out

    @staticmethod
    def _rest_path(arguments: dict) -> str:
        """Validate the caller's ``path`` (and optional ``query`` dict) and return the
        request target. The path MUST keep the request on the tool's loopback origin: it is
        appended to ``http://127.0.0.1:<port>``, so a value that doesn't start with a single
        ``/`` could smuggle a userinfo@host (``@evil``) or a protocol-relative host
        (``//evil``) into the authority. Reject those, plus anything but printable ASCII:
        control chars (CR/LF/tab/NUL) enable request smuggling, and a non-ASCII byte would
        otherwise raise deeper in http.client; a real path encodes those as %XX."""
        path = arguments.get("path")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise RuntimeError("rest call needs a 'path' argument starting with a single '/'")
        # allow only printable ASCII (0x21-0x7e); rejects control chars, space, DEL, non-ASCII
        if "\\" in path or any(not (0x21 <= ord(c) <= 0x7e) for c in path):
            raise RuntimeError("rest path contains invalid characters (use %XX encoding)")
        query = arguments.get("query")
        if isinstance(query, dict) and query:
            pairs = urllib.parse.urlencode({str(k): str(v) for k, v in query.items()})
            path = path + ("&" if "?" in path else "?") + pairs
        return path

    @staticmethod
    def _parse_body(raw: bytes, ctype: str):
        """Decode the tool's response body: parsed JSON when it says JSON, else text."""
        text = raw.decode("utf-8", "replace")
        if "application/json" in ctype:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return text
