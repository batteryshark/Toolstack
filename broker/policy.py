"""Policy (the Policy module seam): allow / review / deny per (tool, operation),
default-deny.

A policy is a plain dict, stored per caller:

    {"tools": {"<tool>": {"<op>": "allow" | "review"}}}

Anything not explicitly listed is denied. Pure logic — no I/O — so it is trivial
to test. (Temporary grants / JIT elevation are a later step.)
"""

from __future__ import annotations

ALLOW = "allow"
REVIEW = "review"
DENY = "deny"


def decide(policy: dict, tool: str, op: str) -> str:
    """Return ALLOW, REVIEW, or DENY for a (tool, op) under a caller policy.

    Missing tool, missing op, or any unrecognized effect -> DENY (fail closed).
    """
    effect = policy.get("tools", {}).get(tool, {}).get(op)
    return effect if effect in (ALLOW, REVIEW) else DENY
