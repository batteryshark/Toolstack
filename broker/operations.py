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


def build_policy(allow, review) -> dict:
    """Build a caller policy from ``allow`` / ``review`` op specs (e.g. ``"echo.say"``).

    ``allow`` wins over ``review`` when both name the same op. The shape matches
    what :meth:`broker.store.Store.set_policy` expects and the policy engine reads.
    """
    tools: dict[str, dict[str, str]] = {}
    for spec in review or []:
        tool, _, op = spec.partition(".")
        tools.setdefault(tool, {})[op] = "review"
    for spec in allow or []:
        tool, _, op = spec.partition(".")
        tools.setdefault(tool, {})[op] = "allow"
    return {"tools": tools}


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


def create_caller(store: Store, name: str, allow, review, operator: str) -> str:
    """Create a caller with an initial token and policy; return the raw token once."""
    caller_id = store.add_caller(name)
    token = secrets.token_urlsafe(32)
    store.add_token(caller_id, hash_token(token))
    store.set_policy(caller_id, build_policy(allow, review))
    record_admin_event(store, operator, "caller_created", {"name": name})
    return token


def revoke_caller(store: Store, name: str, operator: str) -> None:
    require_caller(store, name)
    store.revoke_caller(name)
    record_admin_event(store, operator, "caller_revoked", {"name": name})


def set_policy(store: Store, name: str, allow, review, operator: str) -> None:
    caller = require_caller(store, name)
    store.set_policy(caller["id"], build_policy(allow, review))
    record_admin_event(store, operator, "policy_changed", {"name": name})


def issue_token(store: Store, name: str, operator: str) -> str:
    """Issue an additional token for an existing caller; return the raw token once."""
    caller = require_caller(store, name)
    token = secrets.token_urlsafe(32)
    store.add_token(caller["id"], hash_token(token))
    record_admin_event(store, operator, "token_issued", {"name": name})
    return token


def revoke_token(store: Store, prefix: str, operator: str) -> int:
    """Revoke tokens whose hash starts with ``prefix``; return how many were revoked."""
    count = store.revoke_token_by_prefix(prefix)
    if count:
        record_admin_event(store, operator, "token_revoked", {"prefix": prefix, "count": count})
    return count
