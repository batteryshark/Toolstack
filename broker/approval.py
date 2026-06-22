"""Approval contract types (the broker side of the approval-surface adapter).

`OperationCard` is the redacted prompt the broker hands a surface; it describes
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
    details: str | None = None  # the redacted request the agent sent (so two calls that differ
    #                             only in body are distinguishable; never holds a resolved secret)


@dataclass(frozen=True)
class SurfaceState:
    outcome: str  # PENDING / APPROVED / REJECTED / EXPIRED / CANCELLED
    approver: str | None = None
    note: str | None = None
    decided_at: str | None = None  # when the human answered, per the surface (ISO 8601)


def build_card(request_id: int, caller: str, tool: str, op: str, risk: str,
               reason: str, justification: str | None = None,
               target: str | None = None, details: str | None = None) -> OperationCard:
    # For a rest call the path is part of what's being approved; show it so the human sees
    # "Approve kv.DELETE /items/42", not a blank verb. (A path is a resource locator, not a
    # secret argument, so it belongs on the card.) `details` is the redacted request body so two
    # calls that differ only in body are distinguishable; the broker never holds a resolved secret.
    label = f"{tool}.{op}" + (f" {target}" if target else "")
    return OperationCard(
        request_id=request_id,
        title=f"Approve {label} for caller {caller}",
        caller=caller,
        tool=tool,
        op=op,
        risk=risk,
        reason=reason,
        justification=justification,
        details=details,
    )
