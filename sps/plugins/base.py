"""Plugin harness ABC.

Plugins connect to one secret backend and translate CS_TUPLE lookups
(get_secret / write_secret) into whatever wire protocol the backend speaks.
The ABC lists the contract; only plugins that implement all three methods
can be instantiated (Python's ABC behavior raises TypeError at __init__ for
incomplete subclasses).

`connect` returns a ready object (often `self`). It may also be a no-op for
backends that don't pre-connect (e.g. localfile). This matches the guidance's
plugin shape.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class SPSSecretsPlugin(ABC):
    @abstractmethod
    def connect(self):
        """Initialize any backend session (e.g. acquire an access token).
        Return a ready object (typically self)."""

    @abstractmethod
    def get_secret(self, field: str, item: str) -> str:
        """Resolve a single secret value for the given (field, item)."""

    @abstractmethod
    def write_secret(self, field: str, item: str, value: str) -> None:
        """Patch a single secret value for the given (field, item)."""
