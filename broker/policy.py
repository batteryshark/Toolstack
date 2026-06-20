"""Policy (the Policy module seam): allow / review / deny, default-deny.

A policy is a plain dict, stored per caller:

    {"tools": {"<tool>": {"<key>": "allow" | "review" | "deny"}}}

For api / mcp tools the key is the operation name, matched exactly. For a **rest**
(verb-as-op passthrough) tool the key may additionally scope by request path, so a
caller can be allowed some paths and not others:

    "<VERB>"              -> that verb on ANY path
    "<VERB> <path-glob>"  -> that verb on paths matching the glob

Path globs are segment-aware: ``*`` matches within a single path segment (no ``/``),
``**`` matches across segments (e.g. ``/items/*`` matches ``/items/42`` but not
``/items/42/sub``; ``/items/**`` matches both). When several rules match one request
the **most specific** pattern wins (most literal characters, then fewest wildcards);
a genuine specificity tie resolves to the **most restrictive** effect. Anything not
matched is denied.

Specificity is measured by literal length, so a ``deny`` does NOT automatically win: a
longer-literal-prefix ``allow`` (e.g. ``/reports/quarterly/**``) can out-rank a shorter
``deny`` (e.g. ``/reports/**/secret``). For a guaranteed block, make the deny at least as
literal-heavy as any overlapping allow: an exact key is the surest.

An explicit ``"deny"`` is meaningful for rest (carve a hole inside a broader allow);
for api / mcp, leaving an op unlisted denies it just as before. Pure logic, no I/O.
"""

from __future__ import annotations

import re
from functools import lru_cache

ALLOW = "allow"
REVIEW = "review"
DENY = "deny"

_RANK = {DENY: 0, REVIEW: 1, ALLOW: 2}  # higher == less restrictive


def decide(policy: dict, tool: str, op: str, path: str | None = None) -> str:
    """Return ALLOW, REVIEW, or DENY for a (tool, op[, path]) under a caller policy.

    ``path`` is supplied only for a rest call (the request path). With it, the op's
    path-scoped rules are matched and the most-specific wins. Without it (api / mcp, or
    a discovery / preview listing) the op is permitted if ANY of its rules permits it
    (the least-restrictive effect), so a path-scoped verb still lists as usable.

    Missing tool / op, no matching rule, or an unrecognized effect -> DENY (fail closed).
    """
    rules = policy.get("tools", {}).get(tool, {})
    candidates = []  # (pattern, effect) for every key belonging to this op
    for key, effect in rules.items():
        verb, _, pattern = key.partition(" ")
        if verb == op:
            candidates.append((pattern.strip() or "**", _norm(effect)))
    if not candidates:
        return DENY
    if path is None:
        # api / mcp (a single exact key) or a discovery listing: usable if any rule
        # permits -> least restrictive.
        return max((e for _, e in candidates), key=lambda e: _RANK[e])
    matching = [(p, e) for p, e in candidates if _match(p, path)]
    if not matching:
        return DENY
    best = max(_specificity(p) for p, _ in matching)
    tied = [e for p, e in matching if _specificity(p) == best]
    return min(tied, key=lambda e: _RANK[e])  # specificity tie -> most restrictive


def _norm(effect) -> str:
    return effect if effect in (ALLOW, REVIEW, DENY) else DENY


def _specificity(pattern: str) -> tuple:
    """Higher == more specific. More literal (non-``*``) characters first, then fewer
    wildcards, then a longer pattern: so ``/items/secret`` beats ``/items/*`` beats
    ``/items/**`` beats ``**``."""
    literal = sum(1 for c in pattern if c != "*")
    return (literal, -pattern.count("*"), len(pattern))


def _match(pattern: str, path: str) -> bool:
    return _compile(pattern).match(path) is not None


@lru_cache(maxsize=512)
def _compile(pattern: str):
    # \Z (not $) so a trailing newline in the path can't match a rule whose literal ends
    # the string; the whole path must match, exactly.
    return re.compile("^" + _to_regex(pattern) + r"\Z")


def _to_regex(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        if pattern[i] == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*")        # across segments
                i += 2
            else:
                out.append("[^/]*")     # within one segment
                i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)
