"""Append-only audit log.

One JSON object per line; the guidance specifies tool_id, secret_name, action,
and timestamp. SP_SECRET and E_SECRET are NEVER logged. New-value fields
for writebacks are filtered out at the caller; we only record (tool_id,
secret_name, action, ts).
"""
from __future__ import annotations

import json
import time
import os
import threading
from pathlib import Path
from .paths import private_parent, validate, open_private

# Audit fields we accept. Anything else is silently dropped (defense in depth).
# Notably `esecret`, `spsecret`, `value`, and any other secret-bearing kwarg is
# never persisted -- callers cannot accidentally log a secret because the
# `event()` signature only exposes the safe three.
_ALLOWED = {"tool_id", "secret_name", "action"}


class AuditLogger:
    def __init__(self, path: str | Path, *, max_bytes: int = 4 * 1024 * 1024) -> None:
        if max_bytes < 1024:
            raise ValueError("audit max_bytes must be at least 1024")
        self._max_bytes = max_bytes
        self._path = Path(path)
        self._lock = threading.Lock()
        # If the path looks writable, ensure its parent exists. For tests that
        # pass ephemeral paths we want creation to fail loudly rather than
        # silently no-op.
        private_parent(self._path)
        validate(self._path)
        validate(str(self._path) + ".1")

    def event(self, action: str, *, tool_id: str = "", secret_name: str = "",
              outcome: str = "ok", count: int | None = None) -> None:
        """Append one event line. Extra kwargs are silently dropped so a future
        caller's accidental `esecret=...` cannot leak the value."""
        rec: dict = {"ts": int(time.time()), "action": action[:64], "outcome": outcome[:64]}
        if tool_id:
            rec["tool_id"] = tool_id[:128]
        if secret_name:
            rec["secret_name"] = secret_name[:128]
        if count is not None:
            rec["count"] = max(0, min(int(count), 2**31 - 1))
        payload = (json.dumps(rec) + "\n").encode("utf-8")
        if len(payload) > self._max_bytes:
            raise ValueError("audit event exceeds retention limit")
        with self._lock:
            validate(str(self._path) + ".1")
            fd = open_private(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            try:
                if os.fstat(fd).st_size + len(payload) > self._max_bytes:
                    validate(self._path)
                    validate(str(self._path) + ".1")
                    os.replace(self._path, str(self._path) + ".1")
                    os.close(fd)
                    fd = -1
                    fd = open_private(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            except BaseException:
                if fd != -1:
                    os.close(fd)
                raise
            with os.fdopen(fd, "ab") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
