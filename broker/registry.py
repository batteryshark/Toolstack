"""Tool registry (the Registry-read seam).

Builds the tool catalog from ``toolyard.toml`` files under a tools root. It reads
ONLY the non-secret fields (id, type, operations + their descriptions/args/risk,
entrypoint port) and never looks at a file's ``[[secrets]]`` block — so the broker
stays physically secret-unaware.

`lookup` resolves an op for execution; `describe` / `list_ops` feed agent-facing
tool discovery.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


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
        entry = data.get("entrypoint", {})
        tool_type = data.get("type", "rest")
        port = entry.get("port")
        # A rest tool is invoked at 127.0.0.1:<port>. A missing/invalid port used to
        # register silently as None and only surface as a 502 at call time — fail
        # closed at load instead, naming the offending file and tool. (bool is an int
        # subclass in Python, so exclude it: `port = true` is not a port.)
        if tool_type == "rest" and not (
            isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
        ):
            raise ValueError(
                f"{toml_path}: tool {data.get('id')!r} needs an [entrypoint] port "
                f"(integer 1-65535) for a 'rest' tool; got {port!r}"
            )
        ops = {}
        for o in data.get("operations", []):
            ops[o["name"]] = {
                "risk": o.get("risk", "unknown"),
                "description": o.get("description", ""),
                "args": o.get("args", []),
            }
        # NOTE: data["secrets"] is deliberately never read here.
        catalog[data["id"]] = {"port": port, "type": tool_type, "ops": ops}

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
                ops.append({"tool": tool, "op": op, "risk": meta["risk"],
                            "description": meta["description"]})
        return ops
