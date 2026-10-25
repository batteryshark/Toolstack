"""Operator provisioning of secret VALUES: read-only inspection only.

The control plane never writes secret values. Operator provisioning lives on
the host via ``python3 -m sps.cli vault-set`` (which authenticates against
the runner's SP_SECRET directly). This module is intentionally read-only and
provides status without fetching values. SPS has no inspection operation,
so provisioned_fields returns None (UNKNOWN), never an empty known list.
"""
from __future__ import annotations


def is_settable() -> bool:
    """The panel never writes; we keep the boolean for the response shape
    so the panel can render the UI without conditional logic, but it
    always returns False now."""
    return False


def provisioned_fields(tool_id: str, declared: list[str]) -> list[str] | None:
    """Which of the tool's declared secret fields currently have a value in
    SPS. Returns None for unknown (the SPS wire format has no
    "list provisioned" op; a future enhancement can add one)."""
    return None
