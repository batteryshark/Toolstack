"""Secret resolution backends.

Phase 2 ships a dev `FileBackend` that reads values from a local TOML file. SOPS
and Infisical are the production backends to add behind the same `resolve()`
interface. Resolved values flow only to the tool (via the runner); they never
reach the broker.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from .config import ToolDef


class FileBackend:
    """Dev backend: a TOML file shaped as ``[<tool_id>]  FIELD = "value"``.

    For real deployments this is a SOPS-encrypted file or Infisical; the contract
    is just ``resolve(tool_def) -> {secret_name: value}``.
    """

    def __init__(self, path: str | Path) -> None:
        with open(path, "rb") as f:
            self._data = tomllib.load(f)

    def resolve(self, tool_def: ToolDef) -> dict[str, str]:
        tool_secrets = self._data.get(tool_def.id, {})
        resolved: dict[str, str] = {}
        for spec in tool_def.secrets:
            if spec.field not in tool_secrets:
                raise KeyError(
                    f"secret backend is missing {tool_def.id}.{spec.field}"
                )
            resolved[spec.name] = str(tool_secrets[spec.field])
        return resolved
