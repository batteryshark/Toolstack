"""Drive the toolyard from the admin panel — list tools and start/stop/restart them.

This reuses toolyard's own modules (``discover`` / ``load`` / ``get_runner`` /
``get_backend``) and, crucially, its **state file**, so the panel and
``python -m toolyard.cli`` stay in agreement about what is running. Tools come from
two places: the tools root (``<root>/*/toolyard.toml``) and an explicit list of tool
directories (``tool_dirs``) that the panel's tool editor can add anywhere on the
server. Secret *values* come from the on-disk secrets file — the panel never handles
them, keeping secrets off the control plane.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

# Reuse the toolyard's single state file so the panel and the CLI never disagree
# about which tools are running.
from toolyard.cli import _load_state, _save_state
from toolyard.config import discover
from toolyard.config import load as load_tool
from toolyard.runner import RunningTool, get_runner
from toolyard.secrets import get_backend


def _all_defs(tools_root: str, tool_dirs=()) -> dict:
    """Every ToolDef keyed by id, from the tools root plus each explicit tool dir
    (an explicit dir wins over a root tool of the same id)."""
    defs = {}
    if tools_root:
        for d in discover(tools_root):
            defs[d.id] = d
    for path in tool_dirs or ():
        toml_path = Path(path) / "toolyard.toml"
        if toml_path.exists():
            d = load_tool(toml_path)
            defs[d.id] = d
    return defs


def list_tools(tools_root: str, tool_dirs=()) -> list[dict]:
    """Every defined tool, annotated with its directory and run state. ``removable``
    is True for tools registered via ``tool_dirs`` (the panel can unregister those);
    tools discovered under the tools root are managed on the filesystem."""
    state = _load_state()
    dir_set = {str(Path(p)) for p in (tool_dirs or ())}
    tools = []
    for d in _all_defs(tools_root, tool_dirs).values():
        record = state.get(d.id)
        alive = False
        if record:
            running = RunningTool(**record)
            alive = get_runner(running.backend).is_alive(running)
        tools.append({
            "id": d.id, "type": d.type, "port": d.port, "path": str(d.path),
            "running": bool(record), "alive": alive,
            "backend": record["backend"] if record else None,
            "removable": str(d.path) in dir_set,
        })
    return tools


def start(tool_id: str, tools_root: str, tool_dirs, secrets_file: str, backend: str = "process") -> None:
    defs = _all_defs(tools_root, tool_dirs)
    if tool_id not in defs:
        raise LookupError(f"unknown tool: {tool_id}")
    state = _load_state()
    if tool_id in state:
        return  # already running
    secrets = get_backend(secrets_file=secrets_file).resolve(defs[tool_id])
    # secret_backend=None -> the runner's write proxy reads $TOOLSTACK_SECRET_BACKEND,
    # the same selector get_backend() just used.
    running = get_runner(backend).start(
        defs[tool_id], secrets, secret_backend=None, secrets_file=secrets_file)
    state[tool_id] = asdict(running)
    _save_state(state)


def stop(tool_id: str) -> None:
    state = _load_state()
    record = state.get(tool_id)
    if not record:
        return
    running = RunningTool(**record)
    get_runner(running.backend).stop(running)
    del state[tool_id]
    _save_state(state)


def restart(tool_id: str, tools_root: str, tool_dirs, secrets_file: str, backend: str = "process") -> None:
    stop(tool_id)
    start(tool_id, tools_root, tool_dirs, secrets_file, backend)
