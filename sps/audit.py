"""Append-only audit log.

One JSON object per line, with bounded rotated history. Credentials and secret
values are never accepted. Registration metadata contains only hashed field/item
identifiers and counts.
"""
from __future__ import annotations

import json
import time
import os
import threading
from pathlib import Path
from .paths import private_parent, validate, open_private

class AuditLogger:
    def __init__(self, path: str | Path, *, max_bytes: int = 4 * 1024 * 1024,
                 generations: int = 5) -> None:
        if max_bytes < 1024:
            raise ValueError("audit max_bytes must be at least 1024")
        self._max_bytes = max_bytes
        if generations < 1:
            raise ValueError("audit generations must be positive")
        self._generations = generations
        self._path = Path(path)
        self._lock = threading.Lock()
        # If the path looks writable, ensure its parent exists. For tests that
        # pass ephemeral paths we want creation to fail loudly rather than
        # silently no-op.
        private_parent(self._path)
        validate(self._path)
        for index in range(1, generations + 1):
            validate(str(self._path) + f".{index}")

    def event(self, action: str, *, tool_id: str = "", secret_name: str = "",
              outcome: str = "ok", count: int | None = None,
              entries: list | None = None, entry_count: int | None = None,
              writable_count: int | None = None) -> None:
        """Append one event line; unknown keyword arguments are refused."""
        rec: dict = {"ts": int(time.time()), "action": action[:64], "outcome": outcome[:64]}
        if tool_id:
            rec["tool_id"] = tool_id[:128]
        if secret_name:
            rec["secret_name"] = secret_name[:128]
        if count is not None:
            rec["count"] = max(0, min(int(count), 2**31 - 1))
        if entries is not None:
            import re
            if any(set(e) != {"field", "item"} or any(
                not isinstance(v, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", v)
                for v in e.values()) for e in entries):
                raise ValueError("audit entries require hashed identifiers")
            rec.update(entries=entries, entry_count=int(entry_count), writable_count=int(writable_count))
        payload = (json.dumps(rec) + "\n").encode("utf-8")
        if len(payload) > self._max_bytes:
            raise ValueError("audit event exceeds retention limit")
        with self._lock:
            validate(str(self._path) + ".1")
            fd = open_private(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            try:
                if os.fstat(fd).st_size + len(payload) > self._max_bytes:
                    validate(self._path)
                    for index in range(1, self._generations + 1):
                        validate(str(self._path) + f".{index}")
                    for index in range(self._generations - 1, 0, -1):
                        source = str(self._path) + f".{index}"
                        if os.path.exists(source):
                            os.replace(source, str(self._path) + f".{index + 1}")
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
