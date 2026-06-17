"""Test helpers: an in-memory broker, a fake runtime, a fake approval surface, and
seeded callers. The fakes keep gateway/lifecycle tests hermetic; HttpRuntime and
NodSurface have their own HTTP-level tests.
"""

import unittest

from broker import approval
from broker.approval import SurfaceState
from broker.audit import AuditLog
from broker.context import BrokerContext
from broker.identity import hash_token
from broker.registry import Registry
from broker.store import Store

_DEFAULT_SURFACE = object()  # sentinel: distinguish "use a fake" from "no surface"


class FakeRuntime:
    """Records calls and echoes arguments; raises for the 'boom' tool."""

    def __init__(self):
        self.calls = []

    def execute(self, tool_op, arguments, request_id, caller_name):
        self.calls.append((tool_op.tool, tool_op.op, arguments, request_id, caller_name))
        if tool_op.tool == "boom":
            raise RuntimeError("simulated tool failure")
        return {"echoed": arguments}


class FakeSurface:
    """In-memory approval surface; the decision is settable via set()."""

    def __init__(self, outcome=approval.PENDING, approver=None, note=None, decided_at=None):
        self.opened = []
        self.cancelled = []
        self._state = SurfaceState(outcome, approver, note, decided_at)

    def open(self, card):
        self.opened.append(card)
        return f"ref-{card.request_id}"

    def poll(self, ref):
        return self._state

    def cancel(self, ref):
        self.cancelled.append(ref)

    def set(self, outcome, approver=None, note=None, decided_at=None):
        self._state = SurfaceState(outcome, approver, note, decided_at)


def make_registry(tools: dict | None = None, port: int = 4600) -> Registry:
    """Build a Registry from the friendly shape {tool: {op: risk}}."""
    catalog = {}
    for tool, ops in (tools or {}).items():
        catalog[tool] = {
            "port": port,
            "type": "rest",
            "ops": {op: {"risk": risk, "description": "", "args": []}
                    for op, risk in ops.items()},
        }
    return Registry(catalog)


def make_ctx(catalog=None, runtime=None, surface=_DEFAULT_SURFACE, approval_ttl=3600.0) -> BrokerContext:
    store = Store(":memory:")
    return BrokerContext(
        store=store,
        registry=make_registry(catalog),
        runtime=runtime or FakeRuntime(),
        audit=AuditLog(store, sink=None),  # quiet during tests
        surface=FakeSurface() if surface is _DEFAULT_SURFACE else surface,
        approval_ttl=approval_ttl,
    )


class BrokerTestCase(unittest.TestCase):
    """Base case whose make_ctx closes the in-memory store after each test."""

    def make_ctx(self, catalog=None, runtime=None, surface=_DEFAULT_SURFACE, approval_ttl=3600.0):
        ctx = make_ctx(catalog=catalog, runtime=runtime, surface=surface, approval_ttl=approval_ttl)
        self.addCleanup(ctx.store.close)
        return ctx


def seed_caller(store, name="hermes", allow=None, review=None) -> str:
    caller_id = store.add_caller(name)
    token = f"token-for-{name}"
    store.add_token(caller_id, hash_token(token))

    tools: dict[str, dict[str, str]] = {}
    for spec in review or []:
        tool, _, op = spec.partition(".")
        tools.setdefault(tool, {})[op] = "review"
    for spec in allow or []:
        tool, _, op = spec.partition(".")
        tools.setdefault(tool, {})[op] = "allow"
    store.set_policy(caller_id, {"tools": tools})
    return token
