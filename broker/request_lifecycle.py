"""Request lifecycle (orchestration): registry -> policy -> execute, with an
approval detour for review-required operations.

- allow  -> execute immediately.
- deny   -> refuse.
- review -> open an approval on the surface and park the request. Execution happens
            later, when the agent polls (`resolve_request`) and the surface confirms
            an approval. The broker enforces its OWN timeout (fail closed) and owns
            approval truth.

Arguments are persisted only while a request is pending approval (needed to run it
after approval) and cleared at any terminal state. They are never audited.
"""

from __future__ import annotations

import logging

import json
import time
from dataclasses import dataclass, replace

from . import approval
from . import policy as policy_rules
from .redaction import redact, redact_request
from .runtime import ToolUnreachable

OK = "ok"
PENDING = "pending_approval"
DENIED = "denied"
NOT_FOUND = "not_found"
FAILED = "failed"
EXPIRED = "expired"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Outcome:
    status: str
    request_id: int | None = None
    result: dict | None = None
    reason: str | None = None
    error: str | None = None
    approver: str | None = None  # who decided (from the approval surface)
    note: str | None = None  # the approver's note, surfaced back to the agent
    decided_at: str | None = None  # when the human answered, per the surface (ISO 8601)


log = logging.getLogger(__name__)

def submit(ctx, caller, tool, op, arguments, correlation_id, reason=None) -> Outcome:
    sweep_expired(ctx)  # lazy GC of stale approvals, the broker has no background worker
    audit = ctx.audit
    tool_op = ctx.registry.lookup(tool, op)
    if tool_op is None:
        audit.record("registry", "tool_lookup_failed", NOT_FOUND, correlation_id,
                     details={"tool": tool, "op": op})
        return Outcome(NOT_FOUND)

    request_id = ctx.store.create_request(correlation_id, caller.id, tool, op, "received")
    received = {"tool": tool, "op": op, "risk": tool_op.risk}
    if reason:
        received["reason"] = redact(reason)  # caller-supplied free text; bounded + masked
    audit.record("request", "received", "accepted", correlation_id,
                 request_id=request_id, details=received)

    decision = policy_rules.decide(ctx.store.policy_for(caller.id), tool, op)

    if decision == policy_rules.DENY:
        ctx.store.update_request(request_id, status="denied")
        audit.record("policy", "decision_deny", DENIED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op})
        return Outcome(DENIED, request_id=request_id, reason="policy")

    if decision == policy_rules.REVIEW:
        audit.record("policy", "decision_review_required", PENDING, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "risk": tool_op.risk})
        return _open_approval(ctx, request_id, caller.name, tool, op, tool_op.risk,
                              arguments, correlation_id, reason)

    # allow
    audit.record("policy", "decision_allow", "ok", correlation_id,
                 request_id=request_id, details={"tool": tool, "op": op})
    return execute_request(ctx, request_id, tool, op, arguments, correlation_id, caller.name)


def _open_approval(ctx, request_id, caller_name, tool, op, risk, arguments, correlation_id,
                   reason=None) -> Outcome:
    if ctx.surface is None:
        ctx.store.update_request(request_id, status="failed", error="approval_unavailable")
        ctx.audit.record("approval", "unavailable", UNAVAILABLE, correlation_id,
                         request_id=request_id, details={"tool": tool, "op": op})
        return Outcome(UNAVAILABLE, request_id=request_id, error="approval_unavailable")

    # keep arguments for deferred execution (control-plane store, never audited)
    ctx.store.update_request(request_id, arguments_json=json.dumps(arguments))
    # the agent's reason (redacted) rides along to the human on the card
    card = approval.build_card(request_id, caller_name, tool, op, risk,
                               reason="policy review", justification=redact(reason),
                               details=redact_request(arguments))
    try:
        ref = ctx.surface.open(card)
    except Exception as exc:
        ctx.store.update_request(request_id, status="failed", error="approval_unavailable",
                                 arguments_json=None)
        ctx.audit.record("approval", "open_failed", UNAVAILABLE, correlation_id,
                         request_id=request_id, details={"tool": tool, "op": op, "error": type(exc).__name__})
        return Outcome(UNAVAILABLE, request_id=request_id, error="approval_unavailable")

    ctx.store.create_approval(request_id, ref, time.time() + ctx.approval_ttl)
    ctx.store.update_request(request_id, status="pending_approval")
    ctx.audit.record("approval", "opened", PENDING, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "risk": risk})
    return Outcome(PENDING, request_id=request_id)


def execute_request(ctx, request_id, tool, op, arguments, correlation_id, caller_name) -> Outcome:
    audit = ctx.audit
    tool_op = ctx.registry.lookup(tool, op)
    if tool_op is None:
        ctx.store.update_request(request_id, status="failed", error="tool_unavailable",
                                 arguments_json=None)
        audit.record("runtime", "execution_failed", FAILED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "error": "unregistered"})
        return Outcome(FAILED, request_id=request_id, error="tool_unavailable")

    ctx.store.update_request(request_id, status="running")
    audit.record("runtime", "execution_started", "accepted", correlation_id,
                 request_id=request_id, details={"tool": tool, "op": op})
    try:
        result = ctx.runtime.execute(tool_op, arguments, request_id, caller_name)
    except ToolUnreachable as exc:  # the broker couldn't reach the tool: it's probably not running
        log.warning("tool %s.%s unreachable: %s", tool, op, exc)
        ctx.store.update_request(request_id, status="failed", error="tool_unreachable",
                                 arguments_json=None)
        audit.record("runtime", "execution_failed", FAILED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "error": "unreachable"})
        return Outcome(FAILED, request_id=request_id, error="tool_unreachable")
    except Exception as exc:  # the tool ran but errored; a tool failure must not crash the broker
        log.warning("tool %s.%s failed: %s: %s", tool, op, type(exc).__name__, exc)
        ctx.store.update_request(request_id, status="failed", error="tool_failed",
                                 arguments_json=None)
        audit.record("runtime", "execution_failed", FAILED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "error": type(exc).__name__})
        return Outcome(FAILED, request_id=request_id, error="tool_failed")

    ctx.store.update_request(request_id, status="completed",
                             result_json=json.dumps(result), arguments_json=None)
    audit.record("runtime", "execution_completed", "ok", correlation_id,
                 request_id=request_id, details={"tool": tool, "op": op})
    return Outcome(OK, request_id=request_id, result=result)


def _expire_approval(ctx, approval_id, request_id, surface_ref, tool, op, correlation_id) -> None:
    """Mark an approval (and its request) expired, withdraw it from the surface (best
    effort), and audit. Shared by the per-request timeout in `resolve_request` and the
    lazy `sweep_expired`, one place that fails an approval closed."""
    ctx.store.update_approval(approval_id, status="expired")
    ctx.store.update_request(request_id, status="expired", arguments_json=None)
    if ctx.surface is not None:
        try:
            ctx.surface.cancel(surface_ref)
        except Exception:
            pass
    ctx.audit.record("approval", "expired", EXPIRED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op})


def sweep_expired(ctx, now=None) -> int:
    """Expire every pending approval past its broker deadline, whether or not its
    request is being polled. The broker has no background worker, so this runs
    lazily (on each `submit` and from `brokerctl sweep` / the admin dashboard) to
    GC requests nobody polls again. Returns the number expired."""
    now = time.time() if now is None else now
    rows = ctx.store.expired_pending_approvals(now)
    for row in rows:
        _expire_approval(ctx, row["id"], row["request_id"], row["surface_ref"],
                         row["tool"], row["op"], row["correlation_id"])
    return len(rows)


def resolve_request(ctx, request_id, now=None) -> Outcome:
    """Advance a pending-approval request: enforce the broker timeout, poll the
    surface, and execute on a confirmed approval. Terminal requests are returned
    as-is. `now` is injectable for testing the timeout.

    This is the engine of the approval flow, and it runs ONLY when the agent polls
    (GET /v1/requests/<id>); there is no background worker. So reading status here
    can mutate state and synchronously forward the call to the tool; a request that
    is never polled stays pending until its deadline."""
    now = time.time() if now is None else now
    req = ctx.store.request(request_id)
    if req is None:
        return Outcome(NOT_FOUND)
    if req["status"] != "pending_approval":
        return _outcome_from_request(req, ctx.store.approval_for_request(request_id))

    approval_row = ctx.store.approval_for_request(request_id)
    correlation_id = req["correlation_id"]
    if approval_row is None:
        return Outcome(PENDING, request_id=request_id)

    # The broker's own timer is authoritative: fail closed past the deadline,
    # ignoring any later surface decision.
    if now >= approval_row["expires_at"]:
        _expire_approval(ctx, approval_row["id"], request_id, approval_row["surface_ref"],
                         req["tool"], req["op"], correlation_id)
        return Outcome(EXPIRED, request_id=request_id)

    state = ctx.surface.poll(approval_row["surface_ref"])
    if state.outcome in (approval.APPROVED, approval.REJECTED):
        # the messenger reported a human decision, recorded distinctly from the
        # broker's own approved/rejected (which the broker owns and could override).
        ctx.audit.record("approval", "surface_decision_received", "ok", correlation_id,
                         request_id=request_id,
                         details={"tool": req["tool"], "op": req["op"], "outcome": state.outcome})

    if state.outcome == approval.APPROVED:
        ctx.store.update_approval(approval_row["id"], status="approved",
                                  approver=state.approver, note=state.note,
                                  decided_at=state.decided_at)
        ctx.audit.record("approval", "approved", "ok", correlation_id, request_id=request_id,
                         details={"tool": req["tool"], "op": req["op"], "approver": state.approver})
        args = json.loads(req["arguments_json"] or "{}")
        caller_name = ctx.store.caller_name(req["caller_id"])
        out = execute_request(ctx, request_id, req["tool"], req["op"], args,
                              correlation_id, caller_name)
        return replace(out, approver=state.approver, note=state.note,
                       decided_at=state.decided_at)

    if state.outcome == approval.REJECTED:
        ctx.store.update_approval(approval_row["id"], status="rejected",
                                  approver=state.approver, note=state.note,
                                  decided_at=state.decided_at)
        ctx.store.update_request(request_id, status="denied", error="approval_rejected",
                                 arguments_json=None)
        ctx.audit.record("approval", "rejected", DENIED, correlation_id, request_id=request_id,
                         details={"tool": req["tool"], "op": req["op"], "approver": state.approver})
        return Outcome(DENIED, request_id=request_id, reason="approval_rejected",
                       approver=state.approver, note=state.note, decided_at=state.decided_at)

    if state.outcome in (approval.EXPIRED, approval.CANCELLED):
        ctx.store.update_approval(approval_row["id"], status=state.outcome)
        ctx.store.update_request(request_id, status="expired", arguments_json=None)
        ctx.audit.record("approval", "expired", EXPIRED, correlation_id,
                         request_id=request_id, details={"tool": req["tool"], "op": req["op"]})
        return Outcome(EXPIRED, request_id=request_id)

    return Outcome(PENDING, request_id=request_id)


def _outcome_from_request(req, approval_row=None) -> Outcome:
    status = req["status"]
    result = json.loads(req["result_json"]) if req["result_json"] else None
    mapping = {
        "completed": OK, "denied": DENIED, "expired": EXPIRED, "failed": FAILED,
        "pending_approval": PENDING, "running": PENDING, "received": PENDING,
    }
    reason = "approval_rejected" if req["error"] == "approval_rejected" else None
    approver = approval_row["approver"] if approval_row else None
    note = approval_row["note"] if approval_row else None
    decided_at = approval_row["decided_at"] if approval_row else None
    return Outcome(mapping.get(status, PENDING), request_id=req["id"],
                   result=result, error=req["error"], reason=reason,
                   approver=approver, note=note, decided_at=decided_at)
