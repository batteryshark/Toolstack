"""Read ONLY dedicated broker-to-tool channel credentials from channels.json.

Never read private runner state or SPS credentials. Separate files do not
isolate unrestricted processes owned by the same OS user.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


def _default_state_path() -> Path:
    channel = os.environ.get("TOOLSTACK_TOOLYARD_CHANNEL_STATE")
    if channel:
        return Path(channel)
    state = os.environ.get("TOOLSTACK_TOOLYARD_STATE")
    if state:
        return Path(state).with_name("channels.json")
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "toolstack" / "toolyard" / "channels.json"


class ToolState:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else _default_state_path()
        self._mtime: float | None = None
        self._by_id: dict[str, str] = {}

    def channel_secret_for(self, tool_id: str) -> str | None:
        """Return the channel secret for `tool_id`, or None if the tool is not
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
                tid: rec["channel_secret"]
                for tid, rec in state.items()
                if isinstance(rec, dict) and isinstance(rec.get("channel_secret"), str)
                and rec["channel_secret"].strip()
            }
            self._mtime = mtime
        except (OSError, ValueError, AttributeError):
            self._by_id = {}
            # Leave mtime untouched so we retry on the next call.
