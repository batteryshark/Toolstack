"""Broker-native MCP endpoint (a second ingress framing for the same authority).

The broker speaks REST natively. This module lets an MCP-native agent reach the very
same tools, over the same trust boundary, WITHOUT the client-side stdio adapter
(`client/mcp_server.py`): it terminates JSON-RPC (MCP) frames at `POST /mcp`, applies
the SAME policy / approval / audit as the REST `/v1/actions` path (it calls the same
`request_lifecycle.submit` and emits the same terminal `request.*` event), and executes
through the same REST runtime. Tools speak REST, so frames are *translated* here — not
blindly forwarded to a tool. The agent's token authenticates the call exactly as for REST
(the gateway authenticates before routing here).

**Stateless and non-blocking, by design.** Each POST is one independent JSON-RPC call —
there is no MCP session id and no batching. A `tools/call` on a review op returns
`pending_approval` + a request id immediately rather than holding the connection open:
identical to the REST 202, and necessary because the broker is single-threaded (one
SQLite connection, one request at a time), so blocking one caller on a human's approval
would freeze every caller. The blocking, poll-until-resolved experience stays in the
per-process stdio adapter, where holding a single connection is safe; an HTTP MCP caller
polls `GET /v1/requests/<id>` for the pending request, exactly as a REST caller does.

Stdlib only. The small schema helpers are intentionally duplicated from the client adapter
so the broker stays independent of the `client` package (same rationale as the broker/
toolyard split): the two are separate deployables that happen to share the MCP shape.
"""

from __future__ import annotations

import json

from . import policy as policy_rules
from . import request_lifecycle as lifecycle

PROTOCOL_VERSION = "2024-11-05"
_JSON_TYPES = {"string", "integer", "number", "boolean", "object", "array"}

# Outcome statuses that make an MCP tools/call an error result. `pending_approval` is NOT
# one of them — it is in-progress, not failed (mirrors the REST 202).
_MCP_FAIL = {lifecycle.DENIED, lifecycle.FAILED, lifecycle.UNAVAILABLE, lifecycle.EXPIRED}


class _MethodNotFound(Exception):
    pass


class _InvalidParams(Exception):
    pass


class _RateLimited(Exception):
    """A tools/call over the per-caller limit. Surfaced as HTTP 429 (like the REST path),
    so it is audited via the gateway's response_returned outcome map — not a JSON-RPC
    method error."""


def _input_schema(args: list) -> dict:
    props = {}
    required = []
    for a in args:
        jtype = a.get("type", "string")
        props[a["name"]] = {"type": jtype if jtype in _JSON_TYPES else "string",
                            "description": a.get("description", "")}
        if a.get("required"):
            required.append(a["name"])
    if not props:
        return {"type": "object"}  # permissive: the tool validates
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _with_reason(schema: dict) -> dict:
    """Advertise the optional `_reason` justification on a review tool's input schema —
    the MCP analogue of the CLI's --reason. Stripped before the tool runs; shown to the
    human approver and audited (redacted)."""
    props = dict(schema.get("properties", {}))
    props["_reason"] = {
        "type": "string",
        "description": ("Why you need this — shown to the human approver and recorded in "
                        "the audit log. Recommended on review ops; not passed to the tool."),
    }
    return {**schema, "type": "object", "properties": props}


def _result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _allowed(ctx, caller):
    """Yield (tool, op, effect) for every op this caller may use (allow/review); denied
    ops are omitted — least privilege, identical to REST discovery."""
    policy = ctx.store.policy_for(caller.id)
    for op in ctx.registry.list_ops():
        effect = policy_rules.decide(policy, op["tool"], op["op"])
        if effect != policy_rules.DENY:
            yield op["tool"], op["op"], effect


def _list_tools(ctx, caller) -> list:
    tools = []
    for tool, op, effect in _allowed(ctx, caller):
        described = ctx.registry.describe(tool, op) or {}
        schema = _input_schema(described.get("args", []))
        description = described.get("description", "")
        if effect == policy_rules.REVIEW:
            description = (description + " (requires human approval)").strip()
            schema = _with_reason(schema)
        tools.append({"name": f"{tool}__{op}", "description": description, "inputSchema": schema})
    return tools


def _registered_ops(ctx):
    return [(op["tool"], op["op"]) for op in ctx.registry.list_ops()]


def _resolve_name(ctx, name: str):
    """MCP tool name (``tool__op``) -> (tool, op). An exact match against the *registry*
    (not the caller's policy) disambiguates a ``__`` inside a tool/op name AND lets a
    policy-denied op still resolve — so the call reaches ``submit``, which audits the denial.
    A name with no registry match falls back to a best-effort split, so a genuinely unknown
    op is still submitted (and audited as ``registry.tool_lookup_failed``). An unparseable
    name (no ``__``) -> (None, None)."""
    registered = {f"{t}__{o}": (t, o) for t, o in _registered_ops(ctx)}
    if name in registered:
        return registered[name]
    tool, sep, op = name.partition("__")
    if sep and tool and op:
        return tool, op
    return None, None


def _call_tool(ctx, caller, correlation_id, params) -> dict:
    # Local import breaks an import cycle: gateway imports this module to route /mcp, and
    # these two helpers shape/audit the outcome identically to the REST action path. Reusing
    # them (rather than duplicating) is what guarantees "audit works the same" (AC).
    from .gateway import _audit_request_terminal, _outcome_body

    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise _InvalidParams("arguments must be an object")
    name = params.get("name", "")

    # Rate-limit every tools/call attempt up front, exactly as REST does for POST
    # /v1/actions — before name resolution, so a flood of unknown names is throttled too.
    if ctx.rate_limiter is not None and not ctx.rate_limiter.allow(caller.id):
        raise _RateLimited()

    tool, op = _resolve_name(ctx, name)
    if tool is None:  # unparseable name — there is no tool.op to submit/audit
        return _result(f'unknown tool "{name}"', is_error=True)

    # `_reason` is adapter metadata, not a tool argument: pull it out (never forwarded to
    # the tool) and pass it as the broker's justification — rides to the approver, audited.
    args = dict(arguments)
    reason = args.pop("_reason", None)
    reason = reason if isinstance(reason, str) and reason.strip() else None

    # The SAME path as REST _action: submit applies policy/approval and writes the same
    # audit trail (request.received, policy.decision_*, then the terminal request.* below).
    outcome = lifecycle.submit(ctx, caller, tool, op, args, correlation_id, reason=reason)
    _audit_request_terminal(ctx, outcome, correlation_id, tool, op)

    # Least privilege at the RESULT layer only: a denied or unknown op reads as "unknown
    # tool" to the caller (never reveal an op they may not use) — but submit() already wrote
    # the same denial/lookup audit REST does, so the probe stays queryable.
    if outcome.status in (lifecycle.DENIED, lifecycle.NOT_FOUND):
        return _result(f'unknown tool "{name}"', is_error=True)
    body = _outcome_body(outcome)
    return _result(json.dumps(body, indent=2), is_error=outcome.status in _MCP_FAIL)


def _dispatch(ctx, caller, correlation_id, method: str, params: dict):
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "toolstack-broker", "version": "0.1.0"},
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": _list_tools(ctx, caller)}
    if method == "tools/call":
        return _call_tool(ctx, caller, correlation_id, params)
    raise _MethodNotFound(method)


def _error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def handle(body, ctx, caller, correlation_id) -> tuple[int, dict]:
    """Handle one MCP JSON-RPC message posted to /mcp. Returns ``(http_status, body)`` —
    the gateway uses the status for the response AND for the audit outcome word. Almost
    everything is HTTP 200 with a JSON-RPC envelope (results and JSON-RPC method errors
    alike, per the JSON-RPC-over-HTTP convention); the exception is a per-caller throttle,
    which is HTTP 429 like the REST path so it audits as `rate_limited`. A notification
    (no id) carries no response body (`{}`). The caller is already authenticated by the
    gateway. Batching is intentionally unsupported."""
    if body is None:  # the gateway passes None for a malformed JSON body
        return 200, _error(None, -32700, "parse error: body is not valid JSON")
    if isinstance(body, list):
        return 200, _error(None, -32600, "invalid request: batch is not supported")
    if not isinstance(body, dict):
        return 200, _error(None, -32600, "invalid request: expected a JSON-RPC object")

    mid = body.get("id")
    is_notification = mid is None  # JSON-RPC: no id => notification (no response)
    method = body.get("method", "")
    params = body.get("params") or {}
    if not isinstance(params, dict):
        return 200, ({} if is_notification else _error(mid, -32602, "params must be an object"))

    try:
        result = _dispatch(ctx, caller, correlation_id, method, params)
    except _RateLimited:
        return 429, ({} if is_notification else _error(mid, -32000, "rate_limited"))
    except _MethodNotFound as exc:
        return 200, ({} if is_notification else _error(mid, -32601, f"method not found: {exc}"))
    except _InvalidParams as exc:
        return 200, ({} if is_notification else _error(mid, -32602, str(exc)))
    except Exception:  # never crash the broker; don't leak internals to the caller
        # HTTP 500 so the gateway audits this as `failed` (its status->outcome map); the
        # caller gets a generic message + the correlation id, never the exception text.
        msg = f"internal error (correlation id {correlation_id})"
        return 500, ({} if is_notification else _error(mid, -32603, msg))

    return 200, ({} if is_notification else {"jsonrpc": "2.0", "id": mid, "result": result})
