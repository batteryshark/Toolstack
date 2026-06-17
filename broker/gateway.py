"""Gateway (the ingress/egress seam): routing, body validation, correlation ids,
authentication, and mapping request outcomes to HTTP.

The boundary rule still holds: ``GET /v1/health`` is the only route open without a
caller; everything else requires authentication and otherwise fails closed. Health
is a liveness probe rather than a decision, so it is deliberately not audited —
clients (including the admin app, on every page render) poll it frequently, and
auditing it would bury the real trail.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from . import mcp
from . import policy as policy_rules
from . import request_lifecycle as lifecycle
from .identity import authenticate, token_fingerprint

# lifecycle terminal status -> (request.* audit event_type, audit outcome word). A single
# terminal request.* event per request makes "what was the outcome" directly queryable,
# rather than inferring it from the producing component's runtime.*/policy.*/approval.* event.
_REQUEST_TERMINAL = {
    "ok": ("completed", "ok"),
    "denied": ("denied", "denied"),
    "failed": ("failed", "failed"),
    "unavailable": ("failed", "failed"),
    "expired": ("expired", "expired"),
}

HEALTH_PATH = "/v1/health"
ACTIONS_PREFIX = "/v1/actions/"
REQUESTS_PREFIX = "/v1/requests/"
TOOLS_PATH = "/v1/tools"
TOOLS_PREFIX = "/v1/tools/"
MCP_PATH = "/mcp"  # broker-native MCP (JSON-RPC) framing; see broker/mcp.py

# request-lifecycle outcome -> HTTP status
_OUTCOME_STATUS = {
    lifecycle.OK: 200,
    lifecycle.PENDING: 202,
    lifecycle.DENIED: 403,
    lifecycle.NOT_FOUND: 404,
    lifecycle.EXPIRED: 200,  # only seen on a status query, never on submit
    lifecycle.FAILED: 502,
    lifecycle.UNAVAILABLE: 503,
}

# HTTP status -> audit outcome word (for the egress event)
_AUDIT_OUTCOME = {
    200: "ok", 202: "accepted", 400: "invalid", 401: "denied",
    403: "denied", 404: "not_found", 429: "rate_limited", 502: "failed", 503: "unavailable",
}


@dataclass(frozen=True)
class Response:
    status: int
    body: dict
    correlation_id: str


def make_correlation_id(headers: dict) -> str:
    """Propagate a caller-supplied correlation id, or mint one. Length-capped so a
    caller cannot smuggle a large value into our logs."""
    supplied = (headers.get("x-correlation-id") or "").strip()
    return supplied[:64] if supplied else uuid.uuid4().hex


def handle(method: str, path: str, headers: dict, body, ctx) -> Response:
    headers = {k.lower(): v for k, v in headers.items()}
    correlation_id = make_correlation_id(headers)

    # Liveness probes (GET /v1/health) are not security decisions and are polled
    # often, so they are intentionally left out of the audit trail.
    audited = not (method == "GET" and path == HEALTH_PATH)

    if audited:
        ctx.audit.record(
            "gateway", "request_received", "accepted", correlation_id,
            details={"method": method, "path": path, "has_bearer": "authorization" in headers},
        )
    response = _route(method, path, headers, body, ctx, correlation_id)
    if audited:
        ctx.audit.record(
            "gateway", "response_returned", _AUDIT_OUTCOME.get(response.status, "failed"),
            correlation_id, details={"status": response.status},
        )
    return response


def _route(method, path, headers, body, ctx, correlation_id) -> Response:
    if method == "GET" and path == HEALTH_PATH:
        return Response(200, {"status": "ok"}, correlation_id)

    bearer = headers.get("authorization")
    caller = authenticate(ctx.store, bearer)
    if caller is None:
        # has_bearer = an Authorization header was present (not that it was a well-formed
        # bearer); token_fp is None unless it parsed as `Bearer <token>`. The two together
        # distinguish "no header" / "malformed header" / "well-formed but unknown token".
        ctx.audit.record("identity", "token_rejected", "denied", correlation_id,
                         details={"has_bearer": bool(bearer),
                                  "token_fp": token_fingerprint(bearer)})
        return Response(401, {"error": "unauthorized"}, correlation_id)
    ctx.audit.record("identity", "token_validated", "ok", correlation_id,
                     details={"caller": caller.name, "token_fp": token_fingerprint(bearer)})

    if method == "POST" and path.startswith(ACTIONS_PREFIX):
        if ctx.rate_limiter is not None and not ctx.rate_limiter.allow(caller.id):
            return Response(429, {"error": "rate_limited"}, correlation_id)
        return _action(path, body, ctx, caller, correlation_id)

    if method == "POST" and path == MCP_PATH:
        # Same authority as REST: authenticated above; policy/approval/audit and rate
        # limiting live inside mcp.handle (rate limiting applies to tools/call only, not
        # the initialize/list/ping handshake — mirroring GET /v1/tools, which is unmetered).
        # mcp.handle returns the HTTP status so a throttle (429) / internal error (500)
        # audits with the right outcome via _AUDIT_OUTCOME, exactly like the REST path.
        status, mcp_body = mcp.handle(body, ctx, caller, correlation_id)
        return Response(status, mcp_body, correlation_id)

    if method == "GET" and path == TOOLS_PATH:
        return _list_tools(ctx, caller, correlation_id)

    if method == "GET" and path.startswith(TOOLS_PREFIX):
        return _describe_tool(path, ctx, caller, correlation_id)

    if method == "GET" and path.startswith(REQUESTS_PREFIX):
        return _request_status(path, ctx, caller, correlation_id)

    return Response(404, {"error": "not_found"}, correlation_id)


def _list_tools(ctx, caller, correlation_id) -> Response:
    """Discovery: the ops this caller may actually use (allow/review), with risk and
    a one-line description. Denied ops are omitted (least privilege)."""
    policy = ctx.store.policy_for(caller.id)
    tools = []
    for op in ctx.registry.list_ops():
        effect = policy_rules.decide(policy, op["tool"], op["op"])
        if effect != policy_rules.DENY:
            tools.append({**op, "effect": effect})
    return Response(200, {"caller": caller.name, "tools": tools}, correlation_id)


def _describe_tool(path, ctx, caller, correlation_id) -> Response:
    """Discovery: one op's args/description, on demand. Denied or unknown ops 404
    (never reveal what the caller can't use)."""
    spec = path[len(TOOLS_PREFIX):]
    parts = spec.split(".")
    if len(parts) != 2 or not all(parts):
        return Response(400, {"error": "invalid",
                              "detail": "expected /v1/tools/<tool>.<op>"}, correlation_id)
    tool, op = parts
    effect = policy_rules.decide(ctx.store.policy_for(caller.id), tool, op)
    if effect == policy_rules.DENY:
        return Response(404, {"error": "not_found"}, correlation_id)
    described = ctx.registry.describe(tool, op)
    if described is None:
        return Response(404, {"error": "not_found"}, correlation_id)
    return Response(200, {**described, "effect": effect}, correlation_id)


def _request_status(path, ctx, caller, correlation_id) -> Response:
    """Poll a request: drives approval resolution and returns the current outcome.
    A status query, so it returns 200 with the status body once the caller owns it."""
    rid = path[len(REQUESTS_PREFIX):]
    if not rid.isdigit():
        return Response(400, {"error": "invalid"}, correlation_id)
    req = ctx.store.request(int(rid))
    if req is None or req["caller_id"] != caller.id:
        # never reveal another caller's request
        return Response(404, {"error": "not_found"}, correlation_id)
    # Only a pending_approval request can transition to terminal here; a re-poll of an
    # already-resolved request must not re-emit its terminal event.
    was_pending = req["status"] == "pending_approval"
    outcome = lifecycle.resolve_request(ctx, int(rid))
    if was_pending:
        _audit_request_terminal(ctx, outcome, correlation_id, req["tool"], req["op"])
    return Response(200, _outcome_body(outcome), correlation_id)


def _action(path, body, ctx, caller, correlation_id) -> Response:
    spec = path[len(ACTIONS_PREFIX):]
    parts = spec.split(".")
    if len(parts) != 2 or not all(parts):
        return Response(400, {"error": "invalid",
                              "detail": "expected /v1/actions/<tool>.<op>"}, correlation_id)
    tool, op = parts

    if not isinstance(body, dict):
        return Response(400, {"error": "invalid",
                              "detail": "body must be a JSON object"}, correlation_id)
    arguments = body.get("arguments", {})
    if not isinstance(arguments, dict):
        return Response(400, {"error": "invalid",
                              "detail": "arguments must be an object"}, correlation_id)

    outcome = lifecycle.submit(ctx, caller, tool, op, arguments, correlation_id,
                               reason=body.get("reason"))
    _audit_request_terminal(ctx, outcome, correlation_id, tool, op)
    return Response(_OUTCOME_STATUS[outcome.status], _outcome_body(outcome), correlation_id)


def _audit_request_terminal(ctx, outcome, correlation_id, tool, op) -> None:
    """Emit the terminal `request.<completed|denied|failed|expired>` event for a request
    that just reached a terminal state. No-op for a still-pending outcome or a missing
    request row, so callers must guard re-polls (don't re-emit for an already-resolved
    request) — see `_request_status`."""
    mapped = _REQUEST_TERMINAL.get(outcome.status)
    if mapped is None or outcome.request_id is None:
        return
    event_type, outcome_word = mapped
    ctx.audit.record("request", event_type, outcome_word, correlation_id,
                     request_id=outcome.request_id, details={"tool": tool, "op": op})


def _outcome_body(outcome) -> dict:
    body = {"status": outcome.status}
    if outcome.request_id is not None:
        body["request_id"] = outcome.request_id
    if outcome.result is not None:
        body["result"] = outcome.result
    if outcome.reason is not None:
        body["reason"] = outcome.reason
    if outcome.error is not None:
        body["error"] = outcome.error
    if outcome.approver is not None:
        body["approver"] = outcome.approver
    if outcome.note is not None:
        body["note"] = outcome.note
    if outcome.decided_at is not None:
        body["decided_at"] = outcome.decided_at
    return body
