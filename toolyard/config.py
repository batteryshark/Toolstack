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
from urllib.parse import urlsplit

# Tool transports this toolyard knows how to run. "api" answers /v1/actions/<op>; "mcp" is
# a streamable-HTTP MCP server; "rest" is the generic REST forwarder. All are served on a
# loopback port. An unknown type is rejected at load; never accepted silently. Mirrors
# broker/registry.py and admin/tool_authoring.py (independent packages, duplicated).
TOOL_TYPES = ("api", "mcp", "rest")
RULE_RESPONSE_TYPES = {"json", "xml", "form", "plaintext"}

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
    item: str | None = None  # backend secret path (Infisical); defaults to the tool id


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
    egress: tuple[str, ...] = ()  # [sandbox] egress: hosts a sandboxed tool may reach outbound


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
    if tool_type == "rest":
        _validate_rest(path, data)
    secrets = tuple(
        SecretSpec(
            s["name"],
            s["field"],
            s.get("writable", False),
            s.get("item"),
        )
        for s in data.get("secrets", [])
    )
    # [sandbox] egress: the outbound hosts a sandboxed tool may reach (enforced by the
    # native runners via the egress proxy). Rejected at load if malformed, like port/id.
    egress = data.get("sandbox", {}).get("egress", [])
    if not isinstance(egress, list) or not all(isinstance(h, str) and h for h in egress):
        raise ValueError(f"{path}: [sandbox] egress must be a list of non-empty host strings")
    return ToolDef(
        id=tool_id,
        type=tool_type,
        port=port,
        command=entry.get("command") or ("python3 -m toolstack_forwarder" if tool_type == "rest" else None),
        image=entry.get("image"),
        secrets=secrets,
        path=path.parent,
        description=data.get("description", ""),
        egress=tuple(egress),
    )


def _validate_rest(path: Path, data: dict) -> None:
    base_url = data.get("base_url")
    if not isinstance(base_url, str) or not base_url:
        raise ValueError(f"{path}: rest tool needs top-level base_url")
    split = urlsplit(base_url)
    if split.scheme not in ("http", "https") or not split.hostname:
        raise ValueError(f"{path}: rest base_url must be an absolute http(s) URL with a host")
    if split.username is not None or split.password is not None:
        raise ValueError(f"{path}: rest base_url must not embed credentials")
    secrets = data.get("secrets", [])
    if not isinstance(secrets, list):
        raise ValueError(f"{path}: rest [[secrets]] must be a list")
    writable = set()
    for item in secrets:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: rest [[secrets]] entries must be tables")
        name = item.get("name")
        if isinstance(name, str):
            if item.get("writable", False) is True:
                writable.add(name)
    for op in data.get("operations", []):
        if not isinstance(op, dict):
            continue
        for rule in op.get("secret_update_rules", []):
            if isinstance(rule, dict) and rule.get("secret_name") not in writable:
                raise ValueError(
                    f"{path}: rest secret_update_rule targets non-writable secret {rule.get('secret_name')!r}"
                )
            if isinstance(rule, dict) and rule.get("response_type") not in RULE_RESPONSE_TYPES:
                raise ValueError(
                    f"{path}: rest secret_update_rule has invalid response_type {rule.get('response_type')!r}"
                )
            if isinstance(rule, dict) and not rule.get("extract_path"):
                raise ValueError(f"{path}: rest secret_update_rule needs extract_path")
            if isinstance(rule, dict) and not rule.get("match_status"):
                raise ValueError(f"{path}: rest secret_update_rule needs match_status")


def discover(root: str | Path) -> list[ToolDef]:
    return [load(p) for p in sorted(Path(root).glob("*/toolyard.toml"))]
