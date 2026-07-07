"""Redaction for the few free-text values that may reach audit or an approval card.

The broker's strongest rule is structural: it never logs raw arguments, results, or
tokens. For free-text that IS surfaced (a caller's `reason`, an approver's note),
`redact()` bounds length and masks obvious secret-like runs so a careless value
can't leak in full.
"""

from __future__ import annotations

import json
import re

_MAX = 280
_MAX_REQUEST = 2000
# Crude secret-ish runs: a bearer token, JWT-like three-part token, or any long
# opaque token (>=32 chars).
_SECRETISH = re.compile(r"(?i)bearer\s+\S+|[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|[A-Za-z0-9_\-]{32,}")


def redact(text, limit: int = _MAX) -> str | None:
    if text is None:
        return None
    text = _SECRETISH.sub("[redacted]", str(text))
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def redact_request(arguments, limit: int = _MAX_REQUEST) -> str | None:
    """A compact, secret-masked rendering of the arguments the agent submitted."""
    if not arguments:
        return None
    try:
        text = json.dumps(arguments, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(arguments)
    return redact(text, limit=limit)
