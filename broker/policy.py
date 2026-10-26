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

def decide(policy: dict, tool: str, op: str) -> str:
    """Return ALLOW, REVIEW, or DENY for a (tool, op) under a caller policy."""
    if "disabled_functions" in policy and "enabled" in policy and tool not in policy["enabled"]:
        return DENY
    if op in policy.get("disabled_functions", {}).get(tool, []):
        return DENY
    rules = policy.get("tools", {}).get(tool, {})
    return _norm(rules.get(op))


def _norm(effect) -> str:
    return effect if effect in (ALLOW, REVIEW, DENY) else DENY
