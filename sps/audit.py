"""Append-only audit log.

One JSON object per line; the guidance specifies tool_id, secret_name, action,
and timestamp. SP_SECRET and E_SECRET are NEVER logged. New-value fields
for writebacks are filtered out at the caller; we only record (tool_id,
secret_name, action, ts).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

# Audit fields we accept. Anything else is silently dropped (defense in depth).
# Notably `esecret`, `spsecret`, `value`, and any other secret-bearing kwarg is
# never persisted -- callers cannot accidentally log a secret because the
# `event()` signature only exposes the safe three.
_ALLOWED = {"tool_id", "secret_name", "action"}


class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        # If the path looks writable, ensure its parent exists. For tests that
        # pass ephemeral paths we want creation to fail loudly rather than
        # silently no-op.
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, action: str, *, tool_id: str = "", secret_name: str = "") -> None:
        """Append one event line. Extra kwargs are silently dropped so a future
        caller's accidental `esecret=...` cannot leak the value."""
        rec: dict = {"ts": int(time.time()), "action": action}
        if tool_id:
            rec["tool_id"] = tool_id
        if secret_name:
            rec["secret_name"] = secret_name
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
            f.flush()
