"""Drive the toolyard from the admin panel: list tools and start/stop/restart them.

This reuses toolyard's own modules (``discover`` / ``load`` / ``get_runner``)
and, crucially, its **state file**, so the panel and ``python -m toolyard.cli``
stay in agreement about what is running. Tools come from two places: the
tools root (``<root>/*/toolyard.toml``) and an explicit list of tool
directories (``tool_dirs``) that the panel's tool editor can add anywhere on
the server.

Phase 5: the runner mints an E_SECRET and registers the tool with SPS at
boot, so secret VALUES no longer flow through the panel. The panel still
shows "is this secret provisioned?" (via the SPS ``provisioned_fields``
call) and supports operator provisioning via the SPS ``write_secret``
op; never sees plaintext on the way.
"""

from __future__ import annotations

import shutil
from dataclasses import asdict
from pathlib import Path

# Reuse the toolyard's single state file so the panel and the CLI never disagree
# about which tools are running.
from toolyard.cli import _load_state, _save_state
from toolyard.config import discover
from toolyard.config import load as load_tool
from toolyard.runner import RunningTool, get_runner

from . import settings


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


def start(tool_id: str, tools_root: str, tool_dirs, backend: str = "process") -> None:
    """Start the tool via the runner. Secrets are resolved by the tool at
    boot (Phase 5: SPS pull), so the panel hands the runner nothing but
    the tool definition."""
    defs = _all_defs(tools_root, tool_dirs)
    if tool_id not in defs:
        raise LookupError(f"unknown tool: {tool_id}")
    state = _load_state()
    if tool_id in state:
        # The state file survives the process, VM, and host. Treat it as running
        # intent, not proof that the recorded runtime still exists.
        recorded = RunningTool(**state[tool_id])
        recorded_runner = get_runner(recorded.backend)
        if recorded_runner.is_alive(recorded):
            return  # genuinely already running
        recorded_runner.stop(recorded)
        del state[tool_id]
        _save_state(state)
    running = get_runner(backend).start(defs[tool_id])
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


def restart(tool_id: str, tools_root: str, tool_dirs, backend: str = "process") -> None:
    stop(tool_id)
    start(tool_id, tools_root, tool_dirs, backend)


def remove(tool_id: str, tools_root: str, tool_dirs=()) -> None:
    """Stop a tool if running, then delete its managed folder under ``tools_root``.

    Only TSR-managed tools (those that live UNDER ``tools_root``, the copy-into-managed-dir
    model) are deletable here. A tool referenced via an external ``tool_dirs`` entry is the
    operator's own folder, so it is left on disk (unregister it by editing ``tool_dirs``). The
    path comes from discovery (its id is validated at ingest), and the under-root check is a
    defence-in-depth guard so this can never ``rmtree`` outside the managed tree."""
    defs = _all_defs(tools_root, tool_dirs)
    if tool_id not in defs:
        raise LookupError(f"unknown tool: {tool_id}")
    tool_path = Path(defs[tool_id].path).resolve()
    root = Path(tools_root).resolve() if tools_root else None
    if root is None or tool_path == root or not tool_path.is_relative_to(root):
        raise ValueError(
            f"tool {tool_id!r} is not managed under the tools root; it was registered from an "
            "external directory; unregister it by removing that path from tool_dirs")
    stop(tool_id)  # kill any running process + drop its state record before deleting the code
    try:
        shutil.rmtree(tool_path)
    except OSError as exc:  # stopped but couldn't delete -> a clear 400, not an opaque 500
        raise ValueError(f"stopped {tool_id!r} but could not delete its folder: {exc}") from exc
