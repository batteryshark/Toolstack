"""Per-caller fixed-window rate limiter (in-memory, single process).

Bounds how many action submissions a caller can make per minute. Disabled when
the limit is <= 0. `now` is injectable for testing. Single-threaded dev server, so
a plain dict is fine; revisit with locking under concurrent serving.
"""

from __future__ import annotations

import time


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self._limit = limit_per_minute
        self._window = 60.0
        self._state: dict = {}  # caller_id -> (window_start, count)

    def allow(self, caller_id, now: float | None = None) -> bool:
        if self._limit <= 0:
            return True
        now = time.time() if now is None else now
        start, count = self._state.get(caller_id, (now, 0))
        if now - start >= self._window:
            start, count = now, 0
        if count >= self._limit:
            return False
        self._state[caller_id] = (start, count + 1)
        return True
