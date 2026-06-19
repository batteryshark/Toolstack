"""Parse `toolyard.toml` into a ToolDef.

This is the same file the broker's registry reads; the toolyard additionally reads
`[entrypoint]` (how to run the tool) and `[[secrets]]` (what to resolve). Stdlib
`tomllib`, so no dependency.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecretSpec:
    name: str  # file the tool reads at $TOOLSTACK_SECRETS_DIR/<name>
    field: str  # field looked up in the secret backend
    writable: bool = False
    vault: str | None = None  # backend project/vault (Infisical); backend may ignore
    item: str | None = None  # backend path/item (Infisical); defaults to the tool id


@dataclass(frozen=True)
class ToolDef:
    id: str
    type: str
    port: int
    command: str | None  # process runner entrypoint
    image: str | None  # docker runner image (built from path if absent)
    secrets: tuple[SecretSpec, ...]
    path: Path  # directory containing toolyard.toml (and the tool's files)
    description: str = ""  # optional tool-level summary (the broker registry ignores it)


def load(toml_path: str | Path) -> ToolDef:
    path = Path(toml_path)
    with open(path, "rb") as f:
        data = tomllib.load(f)
    entry = data.get("entrypoint", {})
    tool_type = data.get("type", "api")
    port = entry.get("port")
    # An api tool is served at 127.0.0.1:<port>; a missing/invalid port would otherwise
    # reach the runner as TOOLSTACK_PORT="None" (process) or `-p 127.0.0.1:None:None`
    # (docker) and fail opaquely — reject it at load instead. This mirrors the broker's
    # registry check (broker/registry.py); the two packages stay independent, so the
    # small predicate is duplicated rather than shared. bool is an int subclass, so a
    # `port = true` must not slip through.
    if tool_type == "api" and not (
        isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
    ):
        raise ValueError(
            f"{path}: tool {data.get('id')!r} needs an [entrypoint] port "
            f"(integer 1-65535) for an 'api' tool; got {port!r}"
        )
    secrets = tuple(
        SecretSpec(
            s["name"],
            s["field"],
            s.get("writable", False),
            s.get("vault"),
            s.get("item"),
        )
        for s in data.get("secrets", [])
    )
    return ToolDef(
        id=data["id"],
        type=tool_type,
        port=port,
        command=entry.get("command"),
        image=entry.get("image"),
        secrets=secrets,
        path=path.parent,
        description=data.get("description", ""),
    )


def discover(root: str | Path) -> list[ToolDef]:
    return [load(p) for p in sorted(Path(root).glob("*/toolyard.toml"))]
