"""Request lifecycle (orchestration): registry -> policy -> execute, with an
approval detour for review-required operations.

- allow  -> execute immediately.
- deny   -> refuse.
- review -> open an approval on the surface and park the request. Execution happens
            later, when the agent polls (`resolve_request`) and the surface confirms
            an approval. The broker enforces its OWN timeout (fail closed) and owns
            approval truth.

Arguments are private while received/pending/executing and cleared at terminal
states. Key tombstones never authorize replay, including after pruning/recovery.
"""

from __future__ import annotations

import logging

import json
import time
from dataclasses import dataclass, replace

from . import approval
from . import policy as policy_rules
from .approval_summary import summarize
from .runtime import NotDispatched
from .redaction import redact

OK = "ok"
PENDING = "pending_approval"
DENIED = "denied"
NOT_FOUND = "not_found"
FAILED = "failed"
EXPIRED = "expired"
UNAVAILABLE = "unavailable"
RECEIVED = "received"
EXECUTING = "executing"
UNKNOWN = "unknown"
CONFLICT = "conflict"
INVALID = "invalid"
RESULT_EXPIRED = "result_expired"


@dataclass(frozen=True)
class Outcome:
    status: str
    request_id: int | None = None
    result: dict | None = None
    reason: str | None = None
    error: str | None = None
    detail: str | None = None
    approver: str | None = None  # who decided (from the approval surface)
    note: str | None = None  # the approver's note, surfaced back to the agent
    decided_at: str | None = None  # when the human answered, per the surface (ISO 8601)
    idempotency_key: str | None = None
    payloads_pruned: bool = False
    reused: bool = False


log = logging.getLogger(__name__)

def submit(ctx, caller, tool, op, arguments, correlation_id, reason=None, idempotency_key=None) -> Outcome:
    try:
        ctx.store.validate_idempotency_key(idempotency_key)
    except ValueError:
        return Outcome(INVALID, error="invalid_idempotency_key")
    out = _submit(ctx, caller, tool, op, arguments, correlation_id, reason, idempotency_key)
    return replace(out, idempotency_key=idempotency_key)


def _submit(ctx, caller, tool, op, arguments, correlation_id, reason, idempotency_key):
    sweep_expired(ctx)  # lazy GC of stale approvals, the broker has no background worker
    audit = ctx.audit
    tool_op = ctx.registry.lookup(tool, op)
    if tool_op is None and idempotency_key is None:
        audit.record("registry", "tool_lookup_failed", NOT_FOUND, correlation_id,
                     details={"tool": tool, "op": op})
        return Outcome(NOT_FOUND)

    if not isinstance(arguments, dict) or (reason is not None and not isinstance(reason, str)):
        return Outcome(INVALID, error="invalid_action")
    reason = reason if reason and reason.strip() else None
    try:
        req, created, conflict = ctx.store.reserve_action(caller, correlation_id, tool, op, arguments,
                                                         reason, tool_op.generation if tool_op else "", idempotency_key)
    except (ValueError, TypeError):
        return Outcome(INVALID, error="invalid_action_or_key")
    except PermissionError:
        return Outcome(DENIED, reason="authority")
    request_id = req["id"]
    if conflict:
        return Outcome(CONFLICT, request_id=request_id, error="idempotency_conflict")
    if not created:
        # A retry NEVER advances received or polls approval. Explicit status poll
        # is the only approval-advancing route. Crashes are not replay permission.
        return replace(_outcome_from_request(req, ctx.store.approval_for_request(request_id)), reused=True)
    if tool_op is None:
        ctx.store.update_request(request_id, status="not_found", arguments_json=None)
        return Outcome(NOT_FOUND, request_id=request_id)
    received = {"tool": tool, "op": op, "risk": tool_op.risk, "has_idempotency_key": idempotency_key is not None}
    if reason:
        received["reason_provided"] = True  # never log arbitrary free text
    audit.record("request", "received", "accepted", correlation_id,
                 request_id=request_id, details=received)

    decision = policy_rules.decide(ctx.store.policy_for(caller.id), tool, op)

    if decision == policy_rules.DENY:
        ctx.store.update_request(request_id, status="denied", arguments_json=None)
        audit.record("policy", "decision_deny", DENIED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op})
        return Outcome(DENIED, request_id=request_id, reason="policy")

    if tool_op.type == "rest":
        from .gateway import _validate_rest_arguments
        invalid = _validate_rest_arguments(tool_op, arguments)
        if invalid is not None:
            ctx.store.update_request(request_id, status="invalid", error="invalid_envelope", arguments_json=None)
            return Outcome(INVALID, request_id=request_id, error="invalid_envelope", detail=invalid)

    if decision == policy_rules.REVIEW:
        audit.record("policy", "decision_review_required", PENDING, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "risk": tool_op.risk})
        return _open_approval(ctx, request_id, caller.name, tool, op, tool_op,
                              arguments, correlation_id, reason)

    # allow
    audit.record("policy", "decision_allow", "ok", correlation_id,
                 request_id=request_id, details={"tool": tool, "op": op})
    current_op = ctx.registry.lookup(tool, op)
    if not ctx.store.claim_received(request_id, current_op.generation if current_op else None, caller, req["request_digest"]):
        return _outcome_from_request(ctx.store.request(request_id))
    return execute_request(ctx, request_id, tool, op, arguments, correlation_id, caller.name, claimed_op=current_op)


def _open_approval(ctx, request_id, caller_name, tool, op, tool_op, arguments, correlation_id,
                   reason=None) -> Outcome:
    if ctx.surface is None:
        ctx.store.update_request(request_id, status="failed", error="approval_unavailable")
        ctx.audit.record("approval", "unavailable", UNAVAILABLE, correlation_id,
                         request_id=request_id, details={"tool": tool, "op": op})
        return Outcome(UNAVAILABLE, request_id=request_id, error="approval_unavailable")

    # keep arguments for deferred execution (control-plane store, never audited)
    req = ctx.store.request(request_id)
    digest = req["request_digest"]  # atomically bound at initial reservation
    card = approval.build_card(request_id, caller_name, tool, op, tool_op.risk,
                               reason="policy review", justification=None,
                               details=summarize(arguments, tool_op.approval_fields), endpoint=_rest_endpoint(tool_op),
                               installation_id=ctx.store.installation_id, request_digest=digest,
                               operation_generation=tool_op.generation)
    try:
        ref = ctx.surface.open(card)
    except Exception as exc:
        ctx.store.update_request(request_id, status="failed", error="approval_unavailable",
                                 arguments_json=None)
        ctx.audit.record("approval", "open_failed", UNAVAILABLE, correlation_id,
                         request_id=request_id, details={"tool": tool, "op": op, "error": type(exc).__name__})
        return Outcome(UNAVAILABLE, request_id=request_id, error="approval_unavailable")

    ctx.store.create_approval(request_id, ref, time.time() + ctx.approval_ttl, request_digest=digest)
    ctx.store.update_request(request_id, status="pending_approval")
    ctx.audit.record("approval", "opened", PENDING, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "risk": tool_op.risk})
    return Outcome(PENDING, request_id=request_id)


def execute_request(ctx, request_id, tool, op, arguments, correlation_id, caller_name, *, claimed_op=None) -> Outcome:
    audit = ctx.audit
    req = ctx.store.request(request_id)
    if req is None or req["status"] != "executing" or claimed_op is None:
        return Outcome(FAILED, request_id=request_id, error="execution_not_claimed")
    tool_op = claimed_op or ctx.registry.lookup(tool, op)
    if tool_op is None:
        ctx.store.update_request(request_id, status="failed", error="tool_unavailable",
                                 arguments_json=None)
        audit.record("runtime", "execution_failed", FAILED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op, "error": "unregistered"})
        return Outcome(FAILED, request_id=request_id, error="tool_unavailable")

    audit.record("runtime", "execution_started", "accepted", correlation_id,
                 request_id=request_id, details={"tool": tool, "op": op})
    try:
        result = ctx.runtime.execute(tool_op, arguments, request_id, caller_name)
    except NotDispatched as exc:  # positive evidence action connection was refused
        detail = _error_detail(exc)
        log.warning("tool %s.%s unreachable: %s", tool, op, detail)
        ctx.store.update_request(request_id, status="failed", error="tool_unreachable",
                                 arguments_json=None)
        audit.record("runtime", "execution_failed", FAILED, correlation_id,
                     request_id=request_id,
                     details={"tool": tool, "op": op, "error": "unreachable", "detail": detail})
        return Outcome(FAILED, request_id=request_id, error="tool_unreachable", detail=detail)
    except Exception as exc:  # dispatch may have happened; never promise safe replay
        detail = _error_detail(exc)
        log.warning("tool %s.%s outcome unknown: %s", tool, op, detail)
        ctx.store.update_request(request_id, status="unknown", error="execution_outcome_unknown",
                                 arguments_json=None)
        audit.record("runtime", "execution_unknown", UNKNOWN, correlation_id,
                     request_id=request_id,
                     details={"tool": tool, "op": op, "error": type(exc).__name__, "detail": detail})
        return Outcome(UNKNOWN, request_id=request_id, error="execution_outcome_unknown", detail=detail)

    ctx.store.update_request(request_id, status="completed",
                             result_json=json.dumps(result), arguments_json=None)
    details = {"tool": tool, "op": op}
    if tool_op.type == "rest":
        details.update({
            "outbound_host": tool_op.base_url_host,
            "outbound_verb": tool_op.verb,
            "outbound_path_template": tool_op.path_template,
            "outbound_status": result.get("status") if isinstance(result, dict) else None,
        })
    audit.record("runtime", "execution_completed", "ok", correlation_id,
                 request_id=request_id, details=details)
    return Outcome(OK, request_id=request_id, result=result)


def _rest_endpoint(tool_op) -> str | None:
    if tool_op.type != "rest":
        return None
    bits = [tool_op.verb or "", tool_op.base_url_host or "", tool_op.path_template or ""]
    return " ".join(b for b in bits if b) or None


def _error_detail(exc: Exception) -> str:
    # Exception messages can contain workload bodies, paths or credentials.
    # Stable classification only; heuristic masking is not a secrecy boundary.
    return type(exc).__name__


def _expire_approval(ctx, approval_id, request_id, surface_ref, tool, op, correlation_id, now=None) -> bool:
    """Mark an approval (and its request) expired, withdraw it from the surface (best
    effort), and audit. Shared by the per-request timeout in `resolve_request` and the
    lazy `sweep_expired`, one place that fails an approval closed."""
    if not ctx.store.finish_pending(request_id, "expired", "expired", deadline_only=True, now=now):
        return False
    if ctx.surface is not None:
        try:
            ctx.surface.cancel(surface_ref)
        except Exception:
            pass
    ctx.audit.record("approval", "expired", EXPIRED, correlation_id,
                     request_id=request_id, details={"tool": tool, "op": op})
    return True


def sweep_expired(ctx, now=None) -> int:
    """Expire every pending approval past its broker deadline, whether or not its
    request is being polled. The broker has no background worker, so this runs
    lazily (on each `submit` and from `brokerctl sweep` / the admin dashboard) to
    GC requests nobody polls again. Returns the number expired."""
    now = time.time() if now is None else now
    rows = ctx.store.expired_pending_approvals(now)
    count = 0
    for row in rows:
        count += bool(_expire_approval(ctx, row["id"], row["request_id"], row["surface_ref"],
                                      row["tool"], row["op"], row["correlation_id"], now=now))
    return count


def resolve_request(ctx, request_id, now=None, caller=None) -> Outcome:
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
                         req["tool"], req["op"], correlation_id, now=now)
        return _outcome_from_request(ctx.store.request(request_id), ctx.store.approval_for_request(request_id))

    state = ctx.surface.poll(approval_row["surface_ref"])
    state = replace(state, note=redact(state.note))
    after_poll = max(now, time.time())
    current_req = ctx.store.request(request_id)
    current_approval = ctx.store.approval_for_request(request_id)
    if current_req["status"] != "pending_approval" or current_approval["status"] != "pending":
        return _outcome_from_request(current_req, current_approval)
    if after_poll >= current_approval["expires_at"]:
        _expire_approval(ctx, current_approval["id"], request_id, current_approval["surface_ref"],
                         req["tool"], req["op"], correlation_id, now=after_poll)
        return _outcome_from_request(ctx.store.request(request_id), ctx.store.approval_for_request(request_id))
    if state.outcome in (approval.APPROVED, approval.REJECTED):
        # the messenger reported a human decision, recorded distinctly from the
        # broker's own approved/rejected (which the broker owns and could override).
        ctx.audit.record("approval", "surface_decision_received", "ok", correlation_id,
                         request_id=request_id,
                         details={"tool": req["tool"], "op": req["op"], "outcome": state.outcome})

    if state.outcome == approval.APPROVED:
        tool_op = ctx.registry.lookup(req["tool"], req["op"])
        # Polling may block while another process changes authority or cancels.
        if not ctx.store.claim_approval(request_id, tool_op.generation if tool_op else None,
                                        state, max(now, time.time()), caller=caller):
            return _outcome_from_request(ctx.store.request(request_id),
                                         ctx.store.approval_for_request(request_id))
        ctx.audit.record("approval", "approved", "ok", correlation_id, request_id=request_id,
                         details={"tool": req["tool"], "op": req["op"], "approver": state.approver})
        args = json.loads(req["arguments_json"] or "{}")
        caller_name = ctx.store.caller_name(req["caller_id"])
        out = execute_request(ctx, request_id, req["tool"], req["op"], args,
                               correlation_id, caller_name, claimed_op=tool_op)
        return replace(out, approver=state.approver, note=state.note,
                       decided_at=state.decided_at)

    if state.outcome == approval.REJECTED:
        changed = ctx.store.finish_pending(request_id, "denied", "rejected", error="approval_rejected",
                                           state=state, now=max(now, time.time()))
        if not changed:
            return _outcome_from_request(ctx.store.request(request_id), ctx.store.approval_for_request(request_id))
        current = ctx.store.approval_for_request(request_id)
        out = _outcome_from_request(ctx.store.request(request_id), current)
        ctx.audit.record("approval", current["status"], out.status, correlation_id, request_id=request_id,
                         details={"tool": req["tool"], "op": req["op"], "approver": state.approver})
        return out

    if state.outcome in (approval.EXPIRED, approval.CANCELLED):
        if not ctx.store.finish_pending(request_id, "expired", state.outcome, now=max(now, time.time())):
            return _outcome_from_request(ctx.store.request(request_id), ctx.store.approval_for_request(request_id))
        ctx.audit.record("approval", "expired", EXPIRED, correlation_id,
                         request_id=request_id, details={"tool": req["tool"], "op": req["op"]})
        return _outcome_from_request(ctx.store.request(request_id), ctx.store.approval_for_request(request_id))

    return _outcome_from_request(ctx.store.request(request_id), ctx.store.approval_for_request(request_id))


def _outcome_from_request(req, approval_row=None) -> Outcome:
    status = req["status"]
    result = json.loads(req["result_json"]) if req["result_json"] else None
    mapping = {
        "completed": OK, "denied": DENIED, "expired": EXPIRED, "failed": FAILED,
        "pending_approval": PENDING, "running": EXECUTING, "executing": EXECUTING,
        "received": RECEIVED, "unknown": UNKNOWN, "result_expired": RESULT_EXPIRED,
        "not_found": NOT_FOUND, "invalid": INVALID,
    }
    reason = "approval_rejected" if req["error"] == "approval_rejected" else None
    approver = approval_row["approver"] if approval_row else None
    note = redact(approval_row["note"]) if approval_row else None
    decided_at = approval_row["decided_at"] if approval_row else None
    return Outcome(mapping.get(status, UNKNOWN), request_id=req["id"],
                   result=result, error=req["error"], reason=reason,
                    approver=approver, note=note, decided_at=decided_at,
                    idempotency_key=req["idempotency_key"], payloads_pruned=req["pruned_at"] is not None)
