"""Redaction for the few free-text values that may reach audit or an approval card.

The broker's strongest rule is structural: it never logs raw arguments, results, or
tokens. For free-text that IS surfaced (a caller's `reason`, an approver's note),
`redact()` bounds length and masks obvious secret-like runs so a careless value
can't leak in full.
"""

from __future__ import annotations

import re

_MAX = 280
# Crude secret-ish runs: a bearer token, or any long opaque token (>=32 chars).
_SECRETISH = re.compile(r"(?i)bearer\s+\S+|[A-Za-z0-9_\-]{32,}")


def redact(text, limit: int = _MAX) -> str | None:
    if text is None:
        return None
    text = _SECRETISH.sub("[redacted]", str(text))
    if len(text) > limit:
        text = text[:limit] + "..."
    return text
