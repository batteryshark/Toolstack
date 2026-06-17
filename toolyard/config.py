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


def load(toml_path: str | Path) -> ToolDef:
    path = Path(toml_path)
    with open(path, "rb") as f:
        data = tomllib.load(f)
    entry = data.get("entrypoint", {})
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
        type=data.get("type", "rest"),
        port=entry.get("port"),
        command=entry.get("command"),
        image=entry.get("image"),
        secrets=secrets,
        path=path.parent,
    )


def discover(root: str | Path) -> list[ToolDef]:
    return [load(p) for p in sorted(Path(root).glob("*/toolyard.toml"))]
