"""Tool runtime (the execution seam): forward an approved call to the tool
container on ``127.0.0.1:<port>``.

Two tool transports share this seam, dispatched on ``ToolOp.type``:

* **api**: the broker POSTs ``/v1/actions/<op>`` with the arguments + broker
  context and returns the tool's JSON (the original toolyard contract).
* **mcp**: the tool is a **streamable-HTTP MCP server** listening at
  ``127.0.0.1:<port>/mcp``. The broker is the MCP *client*: it runs the
  ``initialize`` handshake, then issues ``tools/call`` with ``name = <op>``.
  The op is still the unit of policy/approval, so an mcp tool declares its ops
  in ``toolyard.toml`` exactly like an api tool; the runtime maps op -> MCP tool
  name. The MCP ``result`` (content blocks + optional ``structuredContent``) is
  returned to the caller unchanged.
* **rest**: the broker POSTs ``/sendrequest`` to a generic rest forwarder
  process. The forwarder owns outbound HTTP construction, workload secrets, and
  secret-update rules; the broker only supplies the op, arguments, request id,
  caller, and required channel secret.
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
import urllib.request

from .registry import ToolOp


class ToolUnreachable(RuntimeError):
    """The broker could not reach the tool at all (connection refused, DNS, or timeout),
    i.e. the tool process is probably not running. Kept distinct from a tool that ran and
    returned an error, so the lifecycle can report `tool_unreachable` vs `tool_failed`."""


# Protocol version the broker advertises in `initialize`. A streamable-HTTP MCP
# server negotiates down if it speaks an older one; we send a recent dated version.
MCP_PROTOCOL_VERSION = "2025-06-18"

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow a tool-issued redirect. The response (including its Location) is
    controlled by the tool, so following a 3xx would let the tool steer the broker to an
    arbitrary host, an un-mediated request the broker would never have approved (SSRF).
    A 3xx instead surfaces as an HTTPError and is treated as a tool error."""

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
    """Forwards an approved call over HTTP. Handles api and streamable-HTTP mcp tools;
    the constructor and ``execute`` signature are shared, dispatched on ``ToolOp.type``."""

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
            raise ToolUnreachable(f"tool unreachable: {exc.reason}")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError("tool returned non-JSON")

    # -- rest transport: POST /sendrequest to the generic forwarder --------------
    def _execute_rest(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        secret = self._tool_secret(tool_op.tool)
        if not secret:
            raise RuntimeError(f"rest tool {tool_op.tool!r} has no configured channel secret")
        url = f"http://127.0.0.1:{tool_op.port}/sendrequest"
        payload = json.dumps(
            {
                "op": tool_op.op,
                "arguments": arguments,
                "broker_request_id": request_id,
                "caller": {"name": caller_name},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "X-Toolstack-Secret": secret},
            method="POST",
        )
        try:
            with _OPENER.open(req, timeout=self._timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            raise ToolUnreachable(f"tool unreachable: {exc.reason}")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError("tool returned non-JSON")
        if not isinstance(parsed, dict):
            raise RuntimeError("tool returned a non-object envelope")
        if "status" in parsed:
            return parsed
        if parsed.get("error") == "outbound_unreachable":
            raise ToolUnreachable(f"tool outbound unreachable: {parsed.get('reason', '')}")
        if "error" in parsed:
            raise RuntimeError(f"tool forwarder error: {parsed.get('error')}")
        raise RuntimeError("tool returned an invalid envelope")

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
            raise ToolUnreachable(f"tool unreachable: {exc.reason}")
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
