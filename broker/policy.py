"""Policy (the Policy module seam): allow / review / deny, default-deny.

A policy is a plain dict, stored per caller:

    {"tools": {"<tool>": {"<key>": "allow" | "review" | "deny"}}}

The key is the operation name, matched exactly. Missing tool / op, no matching rule,
or an unrecognized effect -> DENY (fail closed). Pure logic, no I/O.
"""

from __future__ import annotations

ALLOW = "allow"
REVIEW = "review"
DENY = "deny"

# Broker-injected secret-cache ops: always allowed for every caller regardless of policy.
# These are infrastructure ops (the tool's SecretClient refreshes its in-memory cache
# from SPS), not user-facing actions; a policy gate would force every operator to
# remember to grant them per caller, and there is no scenario where a caller should be
# denied the ability to refresh a tool's secret cache. The audit log still records the
# call (broker/registry.py / broker/runtime.py record every dispatch).
_AUTO_ALLOW_OPS = frozenset({"refresh", "refresh_one"})


def decide(policy: dict, tool: str, op: str) -> str:
    """Return ALLOW, REVIEW, or DENY for a (tool, op) under a caller policy."""
    if op in _AUTO_ALLOW_OPS:
        return ALLOW
    rules = policy.get("tools", {}).get(tool, {})
    return _norm(rules.get(op))


def _norm(effect) -> str:
    return effect if effect in (ALLOW, REVIEW, DENY) else DENY
