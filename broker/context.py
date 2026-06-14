"""Broker wiring: the dependencies the gateway and request lifecycle share.

A plain holder so call sites take one argument instead of four, and so tests can
assemble an in-memory broker easily.
"""

from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLog
from .registry import Registry
from .runtime import HttpRuntime
from .store import Store


@dataclass
class BrokerContext:
    store: Store
    registry: Registry
    runtime: HttpRuntime  # or any duck-typed runtime (tests inject a fake)
    audit: AuditLog
    surface: object | None = None  # an ApprovalSurface (NodSurface / FakeSurface); None = no review
    approval_ttl: float = 3600.0  # broker-side approval timeout (seconds)
    rate_limiter: object | None = None  # a RateLimiter, or None to disable
