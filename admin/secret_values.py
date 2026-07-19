"""Operator provisioning of secret VALUES: read-only inspection only.

The control plane never writes secret values. Operator provisioning lives on
the host via ``python3 -m sps.cli vault-set`` (which authenticates against
the runner's SP_SECRET directly). This module is intentionally read-only and
just provides the response shape the panel expects (``is_settable``,
``provisioned_fields``). Phase 5 doesn't yet have a "list set secrets" SPS
op, so ``provisioned_fields`` returns ``[]`` -- the panel renders
"set/unset" as "unset" across the board for now (operators run
``python3 -m sps.cli vault-get`` to verify).
"""
from __future__ import annotations


def is_settable() -> bool:
    """The panel never writes; we keep the boolean for the response shape
    so the panel can render the UI without conditional logic, but it
    always returns False now."""
    return False


def provisioned_fields(tool_id: str, declared: list[str]) -> list[str]:
    """Which of the tool's declared secret fields currently have a value in
    SPS. Phase 5 returns ``[]`` (the SPS wire format has no
    "list provisioned" op; a future enhancement can add one)."""
    return []
