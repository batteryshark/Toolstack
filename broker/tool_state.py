"""Read toolyard's state file to discover the E_SECRET each running tool was
provisioned with.

Phase 4 re-sources ``X-Toolstack-Secret`` from the per-tool E_SECRET (which
the runner minted at start, registered with SPS, and wrote to the state file).
This module is the broker-side reader.

The state file is host-local-trust (lives next to the broker, owned by the
runner service account, never crosses a network boundary). The broker does
NOT learn the E_SECRET from SPS -- that would put SP_SECRET (broad) on the
broker, which is the wrong direction.

Lazy + mtime-memoized: a second call within the same mtime is a dict
lookup; a state change (the runner restart-supersedes) is picked up on the
next call. Operator restarts of the broker are idempotent because the file
is unchanged.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


def _default_state_path() -> Path:
    state = os.environ.get("TOOLSTACK_TOOLYARD_STATE")
    if state:
        return Path(state)
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "toolstack" / "toolyard" / "state.json"


class ToolState:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else _default_state_path()
        self._mtime: float | None = None
        self._by_id: dict[str, str] = {}

    def e_secret_for(self, tool_id: str) -> str | None:
        """Return the E_SECRET for `tool_id`, or None if the tool is not
        registered or the state file is missing. Picks up state changes via
        the file's mtime on each call (cheap; the file is small)."""
        self._refresh_if_stale()
        return self._by_id.get(tool_id)

    def tool_ids(self) -> tuple[str, ...]:
        self._refresh_if_stale()
        return tuple(self._by_id.keys())

    def _refresh_if_stale(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            if self._by_id or self._mtime is not None:
                self._by_id = {}
                self._mtime = None
            return
        if self._mtime is not None and mtime == self._mtime:
            return
        # Reread on mtime change. Errors clear the cache to a known state.
        try:
            with self._path.open() as f:
                state = json.load(f)
            self._by_id = {
                tid: rec.get("e_secret") or ""
                for tid, rec in state.items()
                if isinstance(rec, dict) and rec.get("e_secret")
            }
            self._mtime = mtime
        except (OSError, ValueError):
            self._by_id = {}
            # Leave mtime untouched so we retry on the next call.
