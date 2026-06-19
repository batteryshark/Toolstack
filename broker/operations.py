"""Operator mutations, shared by ``brokerctl`` (CLI) and the admin web app.

Each function takes a :class:`~broker.store.Store`, performs one mutation, and
records the matching ``admin.*`` audit event with the operator's identity. This
lives apart from ``brokerctl`` so the CLI and the web panel share exactly one
implementation of every mutation — and therefore one audit trail.

A missing caller raises :class:`LookupError` (not ``SystemExit``): the CLI
converts it to ``SystemExit`` for a clean exit, while the web app renders it as
an error banner. Token-returning calls hand back the raw token once; only its
SHA-256 hash is ever persisted (see :mod:`broker.identity`).
"""

from __future__ import annotations

import secrets
import time
import uuid

from .identity import hash_token
from .store import Store


def build_policy(allow, review, deny=None) -> dict:
    """Build a caller policy from ``allow`` / ``review`` / ``deny`` op specs (e.g.
    ``"echo.say"``, or for a rest tool a path-scoped ``"kv.GET /items/**"``).

    A later list wins for the same key, applied review -> allow -> deny, so an explicit
    ``deny`` carves a hole inside a broader grant. The shape matches what
    :meth:`broker.store.Store.set_policy` expects and the policy engine reads.
    """
    tools: dict[str, dict[str, str]] = {}
    for effect, specs in (("review", review), ("allow", allow), ("deny", deny)):
        for spec in specs or []:
            tool, _, op = spec.partition(".")
            tools.setdefault(tool, {})[op] = effect
    return {"tools": tools}


def path_scoped_keys(policy: dict) -> set:
    """The path-scoped op keys in a policy, as ``"<tool>.<key>"`` (a rest key scopes by
    path, so its op part contains a space, e.g. ``"GET /items/**"``)."""
    return {f"{tool}.{key}" for tool, ops in policy.get("tools", {}).items()
            for key in ops if " " in key}


def coarse_update_drops_scope(store: Store, name: str, allow, review, deny=None) -> set:
    """Return the path-scoped keys that a coarse allow/review/deny update would DROP for this
    caller (empty == safe). A path-blind client (the web policy editor) can't express path
    rules, so saving one over a caller that has them would silently flatten them — that entry
    point calls this to refuse. A path-aware client (the macapp, which renders + manages the
    rules) declares itself and is trusted to send the full picture; brokerctl is unguarded."""
    caller = require_caller(store, name)
    prior = path_scoped_keys(store.policy_for(caller["id"]))
    incoming = path_scoped_keys(build_policy(allow, review, deny))
    return prior - incoming


def enabled_tools(policy: dict) -> list[str]:
    """The tools a caller may manage policy for: the explicit ``enabled`` list (set via the
    web "Enabled tools" toggle) plus any tool that already carries granted ops — so a policy
    authored by ``brokerctl set-policy`` (which grants ops but never sets ``enabled``) still
    surfaces its tools in the editor. Sorted, de-duplicated."""
    granted = policy.get("tools", {})
    return sorted(set(policy.get("enabled", [])) | set(granted.keys()))


def set_enabled_tools(store: Store, name: str, enabled, operator: str) -> None:
    """Set which tools a caller may use. Disabling a tool drops its granted ops
    too (so disabling revokes access, not just hides it). The ``enabled`` key is
    only persisted when non-empty, keeping the stored shape unchanged for callers
    with no tools enabled."""
    caller = require_caller(store, name)
    enabled = list(dict.fromkeys(enabled))  # de-dupe, preserve order
    prior = store.policy_for(caller["id"]).get("tools", {})
    tools = {t: ops for t, ops in prior.items() if t in enabled}
    policy: dict = {"tools": tools}
    if enabled:
        policy["enabled"] = enabled
    store.set_policy(caller["id"], policy)
    record_admin_event(store, operator, "tools_changed", {"name": name, "enabled": enabled})


def record_admin_event(store: Store, operator: str, event_type: str, details: dict) -> None:
    """Append an ``admin.<event_type>`` audit event tagged with the operator."""
    store.append_audit(time.time(), "admin", event_type, "ok", uuid.uuid4().hex, None,
                       {"operator": operator, **details})


def require_caller(store: Store, name: str):
    """Return the caller row, or raise ``LookupError`` if there is no such caller."""
    caller = store.caller_by_name(name)
    if caller is None:
        raise LookupError(f"no such caller: {name}")
    return caller


def create_caller(store: Store, name: str, allow, review, operator: str, deny=None) -> str:
    """Create a caller with an initial token and policy; return the raw token once."""
    caller_id = store.add_caller(name)
    token = secrets.token_urlsafe(32)
    store.add_token(caller_id, hash_token(token))
    store.set_policy(caller_id, build_policy(allow, review, deny))
    record_admin_event(store, operator, "caller_created", {"name": name})
    return token


def _cancel_pending_approvals(store: Store, caller_id: int, surface, operator: str,
                              reason: str) -> int:
    """Cancel a caller's pending approvals: mark each terminal in the store — so the
    parked request can never execute even if a human later taps approve — and
    best-effort withdraw it from the approval surface. Returns the count cancelled.

    ``surface`` may be None: ``brokerctl`` / the admin app revoke out of the broker
    process and may hold no live surface, so the store marking IS the security
    guarantee; the surface withdrawal is opportunistic card hygiene."""
    rows = store.pending_approvals_for_caller(caller_id)
    for row in rows:
        store.update_approval(row["id"], status="cancelled")
        store.update_request(row["request_id"], status="expired", arguments_json=None)
        if surface is not None:
            try:
                surface.cancel(row["surface_ref"])
            except Exception:
                pass  # best effort; the store marking already disarmed the request
        store.append_audit(time.time(), "approval", "cancelled", "cancelled",
                           row["correlation_id"], row["request_id"],
                           {"reason": reason, "operator": operator,
                            "tool": row["tool"], "op": row["op"]})
    return len(rows)


def revoke_caller(store: Store, name: str, operator: str, surface=None) -> int:
    """Revoke a caller and cancel its pending approvals. Returns the count cancelled."""
    caller = require_caller(store, name)
    store.revoke_caller(name)
    cancelled = _cancel_pending_approvals(store, caller["id"], surface, operator, "caller_revoked")
    record_admin_event(store, operator, "caller_revoked",
                       {"name": name, "cancelled_approvals": cancelled})
    return cancelled


def set_policy(store: Store, name: str, allow, review, operator: str, deny=None) -> None:
    caller = require_caller(store, name)
    policy = build_policy(allow, review, deny)
    enabled = store.policy_for(caller["id"]).get("enabled")  # preserve tool-enablement
    if enabled:
        policy["enabled"] = enabled
    store.set_policy(caller["id"], policy)
    record_admin_event(store, operator, "policy_changed", {"name": name})


def issue_token(store: Store, name: str, operator: str) -> str:
    """Issue an additional token for an existing caller; return the raw token once."""
    caller = require_caller(store, name)
    token = secrets.token_urlsafe(32)
    store.add_token(caller["id"], hash_token(token))
    record_admin_event(store, operator, "token_issued", {"name": name})
    return token


def rotate_token(store: Store, name: str, operator: str) -> str:
    """Replace a caller's tokens with a single fresh one and return it once.

    Issues the new token first, then revokes every other active token for the caller —
    add-then-revoke so the caller is never momentarily tokenless (its in-flight
    approvals survive the rotation). This enforces one active token per caller; for a
    distinct identity, create a distinct caller."""
    caller = require_caller(store, name)
    token = secrets.token_urlsafe(32)
    new_hash = hash_token(token)
    store.add_token(caller["id"], new_hash)
    revoked = store.revoke_tokens_for_caller(caller["id"], except_hash=new_hash)
    record_admin_event(store, operator, "token_rotated", {"name": name, "revoked": revoked})
    return token


def revoke_token(store: Store, prefix: str, operator: str, surface=None) -> int:
    """Revoke tokens whose hash starts with ``prefix``; return how many were revoked.

    Cancels pending approvals only for callers the revocation leaves with no active
    token — i.e. it fully de-authenticates them. A caller with other live tokens can
    still act, so its in-flight approvals stand."""
    if not prefix.strip():
        return 0  # an empty prefix would LIKE-match every token — refuse to nuke all
    caller_ids = store.caller_ids_for_token_prefix(prefix)
    count = store.revoke_token_by_prefix(prefix)
    if count:
        cancelled = 0
        for caller_id in caller_ids:
            if store.active_token_count(caller_id) == 0:
                cancelled += _cancel_pending_approvals(store, caller_id, surface,
                                                       operator, "token_revoked")
        record_admin_event(store, operator, "token_revoked",
                           {"prefix": prefix, "count": count, "cancelled_approvals": cancelled})
    return count
