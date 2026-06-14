"""Append-only audit log (the Audit module seam), persisted to SQLite.

Every event is written to the store's ``audit_events`` table. The running server
also mirrors events to stderr via a sink, so the boundary is observable; with no
sink (the test default) the log is silent.

Invariant: audit never records raw secrets or tokens. Callers pass redacted
details only (e.g. whether a bearer was present, never its value; tool/op and
status, never arguments or results).
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable


def stderr_sink(event: dict) -> None:
    """Mirror an event to stderr as one JSON line (used by the running server)."""
    sys.stderr.write(json.dumps(event, sort_keys=True) + "\n")
    sys.stderr.flush()


class AuditLog:
    def __init__(self, store, sink: Callable[[dict], None] | None = None) -> None:
        self._store = store
        self._sink = sink

    def record(
        self,
        component: str,
        event_type: str,
        outcome: str,
        correlation_id: str,
        *,
        request_id: int | None = None,
        details: dict | None = None,
    ) -> int:
        at = time.time()
        details = details or {}
        event_id = self._store.append_audit(
            at, component, event_type, outcome, correlation_id, request_id, details
        )
        if self._sink is not None:
            self._sink(
                {
                    "event_id": event_id,
                    "at": at,
                    "component": component,
                    "event_type": event_type,
                    "outcome": outcome,
                    "correlation_id": correlation_id,
                    "request_id": request_id,
                    "details": details,
                }
            )
        return event_id

    def events(self) -> list[dict]:
        return self._store.audit_events()
