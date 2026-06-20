"""In-memory brute-force throttle for the admin login.

The admin is a single-process app, so a process-local guard is enough. It tracks
failed login attempts per client IP and trips a sliding-window lockout once too many
land within the window, plus a global ceiling so a spread-out (many-IP) attack can't
slip under the per-IP limit. A blocked attempt is rejected *before* the password is
checked, so it neither leaks timing nor extends the lockout.

State is process-local and lost on restart — acceptable, since a restart is not
something the unauthenticated login surface can trigger. Shared by the HTML ``/login``
and the JSON ``/api/login`` so the two can't be played off against each other.

The per-IP key is the direct peer (``request.client.host``); behind a shared reverse
proxy or a TLS tunnel that terminates locally, every client collapses into one bucket,
so the per-IP lockout effectively becomes a single shared one and the global ceiling is
the real backstop. That is fine for the operator-scale threat model this targets.
"""

from __future__ import annotations

import threading
import time


class LoginGuard:
    def __init__(self, *, max_per_ip: int = 5, lockout: float = 300.0,
                 global_max: int = 50, global_window: float = 300.0) -> None:
        self.max_per_ip = max_per_ip
        self.lockout = lockout            # sliding window AND the per-IP cool-off, in seconds
        self.global_max = global_max
        self.global_window = global_window
        self._lock = threading.Lock()
        self._ip_fails: dict[str, list[float]] = {}
        self._global_fails: list[float] = []

    def _prune(self, now: float) -> None:
        """Drop aged-out failures so the dicts can't grow without bound. Caller holds the lock."""
        for ip in list(self._ip_fails):
            kept = [t for t in self._ip_fails[ip] if t >= now - self.lockout]
            if kept:
                self._ip_fails[ip] = kept
            else:
                del self._ip_fails[ip]
        self._global_fails = [t for t in self._global_fails if t >= now - self.global_window]

    def retry_after(self, ip: str) -> float:
        """Seconds the caller must wait before another attempt is allowed, or 0.0 if allowed now."""
        now = time.time()
        with self._lock:
            self._prune(now)
            recent = self._ip_fails.get(ip, [])
            if len(recent) >= self.max_per_ip:
                return max(0.0, self.lockout - (now - min(recent)))  # until the oldest ages out
            if len(self._global_fails) >= self.global_max:
                return max(0.0, self.global_window - (now - min(self._global_fails)))
            return 0.0

    def record_failure(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            self._ip_fails.setdefault(ip, []).append(now)
            self._global_fails.append(now)

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._ip_fails.pop(ip, None)
