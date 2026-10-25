"""In-memory TOOL_REGISTRATION pool.

Per the guidance: NOT backed to disk, NOT in memcached/redis. A `kill -9` and
restart loses every registration — that's the point: an SPS that loses its
in-memory pool is the same as every tool being unregistered, so the runner
must re-register on every restart (and it does, see toolyard/runner.py).
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from threading import RLock
from typing import Mapping


@dataclass(frozen=True)
class Registration:
    """A registered tool's record: the E_SECRET plus the CS_TUPLE list."""
    esecret: str
    secret_entries: tuple[Mapping, ...]

    def __post_init__(self):
        object.__setattr__(self, "secret_entries", tuple(
            MappingProxyType(dict(entry)) for entry in self.secret_entries))


class ToolRegistrationStore:
    def __init__(self) -> None:
        self._by_id: dict[str, Registration] = {}
        self._lock = RLock()

    def register(self, tool_id: str, rec: Registration) -> None:
        """Insert or replace. Re-registration is the same call: the runner does
        this on every tool start (TOML secret values may have changed)."""
        with self._lock:
            self._by_id[tool_id] = rec

    def unregister(self, tool_id: str) -> None:
        with self._lock:
            self._by_id.pop(tool_id, None)

    def get(self, tool_id: str) -> Registration | None:
        with self._lock:
            return self._by_id.get(tool_id)

    def ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._by_id.keys())
