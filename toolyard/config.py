"""Parse `toolyard.toml` into a ToolDef.

This is the same file the broker's registry reads; the toolyard additionally reads
`[entrypoint]` (how to run the tool) and `[[secrets]]` (what to resolve). Stdlib
`tomllib`, so no dependency.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Tool transports this toolyard knows how to run. "api" answers /v1/actions/<op>; "mcp" is
# a streamable-HTTP MCP server. Both are served on a loopback port. An unknown type is
# rejected at load; never accepted silently. Mirrors broker/registry.py and
# admin/tool_authoring.py (independent packages, so the set is duplicated, not shared).
TOOL_TYPES = ("api", "mcp")

# A tool id is the routing key and a directory name; it must match this charset, and must NOT
# contain a dot, since the broker splits a policy spec on the FIRST dot into (tool, op), so a
# dotted id like "my.tool" silently misroutes policy. Mirrors broker/registry._ID_RE and
# admin/tool_authoring._ID_RE (independent packages, so the pattern is duplicated, not shared).
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")   # no dots (tool.op routing) or slashes


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
    tool_id = data.get("id")
    # Reject a missing/invalid id at load, naming the file + id; mirrors the broker registry's
    # check (broker/registry.py). A dotted id would slip through here and only misroute policy
    # in the broker later.
    if not (isinstance(tool_id, str) and _ID_RE.match(tool_id)):
        raise ValueError(
            f"{path}: invalid tool id {tool_id!r} (letters, digits, _ or - only; "
            f"no dots: a dot breaks tool.op policy routing)"
        )
    entry = data.get("entrypoint", {})
    tool_type = data.get("type", "api")
    # Reject an unknown/typo'd type at load; never accept it silently (it would otherwise
    # register and only mis-dispatch at call time).
    if tool_type not in TOOL_TYPES:
        raise ValueError(
            f"{path}: tool {data.get('id')!r} has unknown type {tool_type!r} "
            f"(known: {', '.join(TOOL_TYPES)})"
        )
    port = entry.get("port")
    # Every tool type is served on 127.0.0.1:<port> (an api tool answers /v1/actions/<op>;
    # an mcp tool serves streamable-HTTP MCP at /mcp). A missing/invalid port would otherwise
    # reach the runner as TOOLSTACK_PORT="None" (process) or `-p 127.0.0.1:None:None` (docker)
    # and fail opaquely; reject it at load instead. This mirrors the broker's registry check
    # (broker/registry.py); the two packages stay independent, so the small predicate is
    # duplicated rather than shared. bool is an int subclass, so a `port = true` must not slip
    # through.
    if not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535):
        raise ValueError(
            f"{path}: tool {data.get('id')!r} needs an [entrypoint] port "
            f"(integer 1-65535) for a {tool_type!r} tool; got {port!r}"
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
        id=tool_id,
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
