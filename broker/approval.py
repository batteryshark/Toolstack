"""Approval contract types (the broker side of the approval-surface adapter).

`OperationCard` is the redacted prompt the broker hands a surface — it describes
the operation, never raw arguments or secrets. `SurfaceState` is the normalized
answer the broker reads back. See docs/approval-surface-adapter.md.
"""

from __future__ import annotations

from dataclasses import dataclass

# Normalized surface outcomes.
PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"
CANCELLED = "cancelled"


@dataclass(frozen=True)
class OperationCard:
    request_id: int  # doubles as the surface idempotency key
    title: str
    caller: str
    tool: str
    op: str
    risk: str
    reason: str  # why policy routed this to review
    justification: str | None = None  # the agent's (redacted) reason, shown to the human


@dataclass(frozen=True)
class SurfaceState:
    outcome: str  # PENDING / APPROVED / REJECTED / EXPIRED / CANCELLED
    approver: str | None = None
    note: str | None = None


def build_card(request_id: int, caller: str, tool: str, op: str, risk: str,
               reason: str, justification: str | None = None) -> OperationCard:
    return OperationCard(
        request_id=request_id,
        title=f"Approve {tool}.{op} for caller {caller}",
        caller=caller,
        tool=tool,
        op=op,
        risk=risk,
        reason=reason,
        justification=justification,
    )
