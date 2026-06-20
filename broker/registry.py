"""Tool registry (the Registry-read seam).

Builds the tool catalog from ``toolyard.toml`` files under a tools root. It reads
ONLY the non-secret fields (id, type, operations + their descriptions/args/risk,
entrypoint port) and never looks at a file's ``[[secrets]]`` block, so the broker
stays physically secret-unaware.

`lookup` resolves an op for execution; `describe` / `list_ops` feed agent-facing
tool discovery.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Tool transports the broker knows how to route. "api" -> POST /v1/actions/<op>; "mcp" ->
# streamable-HTTP MCP client; "rest" -> verb-as-op passthrough (see broker/runtime.py). An
# unknown type is rejected at load. Mirrors toolyard/config.py and admin/tool_authoring.py
# (independent packages, so the set is duplicated, not shared).
TOOL_TYPES = ("api", "mcp", "rest")

# For a "rest" tool the risk is DEFINED by the verb, not the manifest, so the broker derives
# it here; the approval card and discovery then show the right risk even for a hand-written
# toolyard.toml. Mirrors admin/tool_authoring.REST_VERB_RISK (independent package, duplicated).
REST_VERB_RISK = {"GET": "read", "POST": "write", "PUT": "write",
                  "PATCH": "write", "DELETE": "destructive"}

# A tool id is the routing key and a directory name; it must match this charset, and crucially
# must NOT contain a dot. A policy spec is split on the FIRST dot into (tool, op) (see
# broker/operations.build_policy), so a dotted id like "my.tool" mis-parses and silently
# misroutes its policy. Mirrors admin/tool_authoring._ID_RE (independent packages, duplicated).
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")   # no dots (tool.op routing) or slashes


@dataclass(frozen=True)
class ToolOp:
    tool: str
    op: str
    risk: str
    port: int
    type: str


class Registry:
    def __init__(self, catalog: dict | None = None) -> None:
        # catalog: {tool: {"port": int, "type": str,
        #                  "ops": {op: {"risk", "description", "args"}}}}
        self._catalog = catalog or {}

    @staticmethod
    def _add_toml(catalog: dict, toml_path: Path) -> None:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
        tool_id = data.get("id")
        # Fail closed at load (naming the file + id) on a missing/invalid id, like the port
        # check below. The admin panel enforces this charset; a hand-written toolyard.toml is
        # the unchecked path, where a dotted id would become a catalog key and break tool.op
        # policy routing only later.
        if not (isinstance(tool_id, str) and _ID_RE.match(tool_id)):
            raise ValueError(
                f"{toml_path}: invalid tool id {tool_id!r} (letters, digits, _ or - only; "
                f"no dots: a dot breaks tool.op policy routing)"
            )
        entry = data.get("entrypoint", {})
        tool_type = data.get("type", "api")
        # Reject an unknown/typo'd type at load; never register it silently (it would
        # otherwise resolve to a ToolOp and only mis-dispatch at call time).
        if tool_type not in TOOL_TYPES:
            raise ValueError(
                f"{toml_path}: tool {data.get('id')!r} has unknown type {tool_type!r} "
                f"(known: {', '.join(TOOL_TYPES)})"
            )
        port = entry.get("port")
        # Every tool type is invoked at 127.0.0.1:<port> (an api tool at /v1/actions/<op>, an
        # mcp tool over streamable-HTTP MCP at /mcp). A missing/invalid port used to register
        # silently as None and only surface as a 502 at call time; fail closed at load
        # instead, naming the offending file and tool. (bool is an int subclass in Python, so
        # exclude it: `port = true` is not a port.)
        if not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535):
            raise ValueError(
                f"{toml_path}: tool {data.get('id')!r} needs an [entrypoint] port "
                f"(integer 1-65535) for a {tool_type!r} tool; got {port!r}"
            )
        ops = {}
        for o in data.get("operations", []):
            risk = o.get("risk", "unknown")
            if tool_type == "rest":
                # the verb defines the risk; override the manifest (case-insensitively) so a
                # mislabelled or hand-written rest op can't misrepresent risk on the approval card
                risk = REST_VERB_RISK.get(o["name"].upper(), risk)
            ops[o["name"]] = {
                "risk": risk,
                "description": o.get("description", ""),
                "args": o.get("args", []),
            }
        # NOTE: data["secrets"] is deliberately never read here.
        catalog[tool_id] = {"port": port, "type": tool_type, "ops": ops}

    @classmethod
    def from_tools_root(cls, root: str | Path) -> "Registry":
        catalog: dict[str, dict] = {}
        for toml_path in sorted(Path(root).glob("*/toolyard.toml")):
            cls._add_toml(catalog, toml_path)
        return cls(catalog)

    @classmethod
    def from_sources(cls, root: str | Path | None = None, tool_dirs=()) -> "Registry":
        """Build the catalog from a tools root (globs ``<root>/*/toolyard.toml``)
        and/or an explicit list of tool directories (each holding a
        ``toolyard.toml``). A tool directory wins over a root tool of the same id.
        Either source may be empty."""
        catalog: dict[str, dict] = {}
        if root:
            for toml_path in sorted(Path(root).glob("*/toolyard.toml")):
                cls._add_toml(catalog, toml_path)
        for d in tool_dirs:
            toml_path = Path(d) / "toolyard.toml"
            if toml_path.exists():
                cls._add_toml(catalog, toml_path)
        return cls(catalog)

    def lookup(self, tool: str, op: str) -> ToolOp | None:
        entry = self._catalog.get(tool)
        if entry is None or op not in entry["ops"]:
            return None
        return ToolOp(tool, op, entry["ops"][op]["risk"], entry["port"], entry["type"])

    def describe(self, tool: str, op: str) -> dict | None:
        entry = self._catalog.get(tool)
        if entry is None or op not in entry["ops"]:
            return None
        meta = entry["ops"][op]
        return {"tool": tool, "op": op, "risk": meta["risk"],
                "description": meta["description"], "args": meta["args"]}

    def list_ops(self) -> list[dict]:
        ops = []
        for tool, entry in self._catalog.items():
            for op, meta in entry["ops"].items():
                ops.append({"tool": tool, "op": op, "type": entry["type"], "risk": meta["risk"],
                            "description": meta["description"]})
        return ops
