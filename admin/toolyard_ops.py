"""Drive the toolyard from the admin panel: list tools and start/stop/restart them.

This reuses toolyard's own modules (``discover`` / ``load`` / ``get_runner``)
and, crucially, its **state file**, so the panel and ``python -m toolyard.cli``
stay in agreement about what is running. Tools come from two places: the
tools root (``<root>/*/toolyard.toml``) and an explicit list of tool
directories (``tool_dirs``) that the panel's tool editor can add anywhere on
the server.

The runner registers tools with SPS at boot. Secret values never flow
through this module; provisioning is host-side and inspection may be unknown.
"""

from __future__ import annotations

import shutil
from dataclasses import asdict, replace
from pathlib import Path

# Reuse the toolyard's single state file so the panel and the CLI never disagree
# about which tools are running.
from toolyard.cli import _load_state, _save_state
from toolyard.config import discover, SecretSpec
from toolyard.config import load as load_tool
from toolyard.runner import RunningTool, RunnerStartCleanupError, get_runner

from . import settings


def state_lock():
    """Use the runner's cross-process lock or fail closed until integrated."""
    from toolyard import cli
    lock = getattr(cli, "state_lock", None)
    if lock is None:
        raise RuntimeError("Runner state_lock API unavailable; integrate runner repair first")
    return lock()


class UnrecordedRuntimeError(RuntimeError):
    def __init__(self, running):
        super().__init__("Start could not be recorded and cleanup failed; operator recovery required")
        self.running = running


def _record_or_rollback(state, tool_id, running, runner):
    state[tool_id] = asdict(running)
    try:
        _save_state(state)
    except Exception:
        try:
            runner.stop(running)
        except Exception:
            raise UnrecordedRuntimeError(running) from None
        # Private state may have published before channel-view publication
        # failed. Clear the rolled-back intent as well, under the same lock.
        del state[tool_id]
        _save_state(state)
        raise


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
    dir_set = {str(Path(p).resolve()) for p in (tool_dirs or ())}
    tools = []
    for d in _all_defs(tools_root, tool_dirs).values():
        record = state.get(d.id)
        alive = False
        if record:
            try:
                running = RunningTool(**record)
                alive = get_runner(running.backend).is_alive(running)
            except Exception:
                alive = None  # inspection failure is not proof of death
        tools.append({
            "id": d.id, "type": d.type, "port": d.port, "path": str(d.path),
            "running": bool(record), "alive": alive,
            "state": "unknown" if alive is None else "running" if alive else "crashed" if record else "stopped",
            "health": "unknown" if alive or alive is None else "stopped",
            "backend": record["backend"] if record else None,
            "secrets": [asdict(s) for s in d.secrets],
            "removable": str(Path(d.path).resolve()) in dir_set,
        })
    return tools


def _start(tool_id: str, tools_root: str, tool_dirs, backend: str = "process", *, recovery=False) -> None:
    """Start the tool via the runner. Secrets are resolved by the tool at
    boot (Phase 5: SPS pull), so the panel hands the runner nothing but
    the tool definition."""
    defs = _all_defs(tools_root, tool_dirs)
    if tool_id not in defs:
        raise LookupError(f"unknown tool: {tool_id}")
    state = _load_state()
    if recovery:
        rec = state.get(tool_id, {})
        if rec.get("secret_declarations") is None or not rec.get("manifest_digest"):
            raise ValueError("recorded declarations missing; operator Start required")
        defs[tool_id] = replace(defs[tool_id], secrets=tuple(
            SecretSpec(**s) for s in rec["secret_declarations"]),
            manifest_digest=rec["manifest_digest"])
    if tool_id in state:
        # The state file survives the process, VM, and host. Treat it as running
        # intent, not proof that the recorded runtime still exists.
        recorded = RunningTool(**state[tool_id])
        recorded_runner = get_runner(recorded.backend)
        if recorded_runner.is_alive(recorded):
            return  # genuinely already running
        try:
            recorded_runner.stop(recorded)
        except RunnerStartCleanupError as exc:
            state[tool_id] = asdict(exc.running)
            _save_state(state)
            raise
        del state[tool_id]
        _save_state(state)
    runner = get_runner(backend)
    try:
        running = runner.start(defs[tool_id])
    except Exception as exc:
        # RunnerStartCleanupError contract: a runtime may survive failed start.
        running = getattr(exc, "running", None)
        if isinstance(running, RunningTool):
            _record_or_rollback(state, tool_id, running, runner)
        raise
    _record_or_rollback(state, tool_id, running, runner)


def _stop(tool_id: str) -> None:
    state = _load_state()
    record = state.get(tool_id)
    if not record:
        return
    running = RunningTool(**record)
    try:
        get_runner(running.backend).stop(running)
    except RunnerStartCleanupError as exc:
        state[tool_id] = asdict(exc.running)
        _save_state(state)
        raise
    del state[tool_id]
    _save_state(state)


def restart(tool_id: str, tools_root: str, tool_dirs, backend: str = "process") -> None:
    with state_lock():
        _stop(tool_id)
        _start(tool_id, tools_root, tool_dirs, backend)


def start(tool_id: str, tools_root: str, tool_dirs, backend: str = "process", *, recovery=False) -> None:
    with state_lock():
        _start(tool_id, tools_root, tool_dirs, backend, recovery=recovery)


def record_edited_declarations(tool):
    """An explicit operator edit may change the next recovery registration."""
    import hashlib
    from .tool_authoring import to_toml
    digest = hashlib.sha256(to_toml(tool).encode("utf-8")).hexdigest()
    with state_lock():
        state = _load_state()
        if tool["id"] in state:
            state[tool["id"]]["secret_declarations"] = [dict(s) for s in tool["secrets"]]
            state[tool["id"]]["manifest_digest"] = digest
            _save_state(state)


def stop(tool_id: str) -> None:
    with state_lock():
        _stop(tool_id)


def _remove(tool_id: str, tools_root: str, tool_dirs=()) -> None:
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
    _stop(tool_id)  # caller holds the complete lifecycle lock
    try:
        shutil.rmtree(tool_path)
    except OSError as exc:  # stopped but couldn't delete -> a clear 400, not an opaque 500
        raise ValueError(f"stopped {tool_id!r} but could not delete its folder: {exc}") from exc


def remove(tool_id: str, tools_root: str, tool_dirs=()) -> None:
    with state_lock():
        _remove(tool_id, tools_root, tool_dirs)
