"""Drive the toolyard from the admin panel: list tools and start/stop/restart them.

This reuses toolyard's own modules (``discover`` / ``load`` / ``get_runner`` /
``get_backend``) and, crucially, its **state file**, so the panel and
``python -m toolyard.cli`` stay in agreement about what is running. Tools come from
two places: the tools root (``<root>/*/toolyard.toml``) and an explicit list of tool
directories (``tool_dirs``) that the panel's tool editor can add anywhere on the
server. The panel never handles secret values, keeping them off the control plane.
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
from toolyard.secrets import get_backend, protect_secret_memory

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


def start(tool_id: str, tools_root: str, tool_dirs, secrets_file: str, backend: str = "process") -> None:
    defs = _all_defs(tools_root, tool_dirs)
    if tool_id not in defs:
        raise LookupError(f"unknown tool: {tool_id}")
    state = _load_state()
    if tool_id in state:
        return  # already running
    # Scope the backend to this tool's own machine identity; a tool with no secrets
    # needs no backend (and so no Infisical credential) at all.
    secrets = {}
    if defs[tool_id].secrets:
        protect_secret_memory()
        secrets = get_backend(secrets_file=secrets_file,
                              tool_def=defs[tool_id]).resolve(defs[tool_id])
    # Pass the configured backend name to the runner's write proxy explicitly, rather than
    # leaving it to re-read $TOOLSTACK_SECRET_BACKEND in the child: same selector get_backend()
    # just used, but no reliance on the env being set in the spawned process.
    running = get_runner(backend).start(
        defs[tool_id], secrets,
        secret_backend=settings.secret_backend(), secrets_file=secrets_file)
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


def reconcile(tools_root: str, tool_dirs, secrets_file: str,
              backend: str = "process") -> dict[str, list[str]]:
    """Restore recorded tools whose process or ephemeral secret injection is gone.

    Docker secrets live only in the container's tmpfs. A daemon or host restart can
    recreate a recorded container without that tmpfs content, so DockerRunner exposes a
    marker check that does not read any secret. Process runners use the equivalent
    RAM-backed files check. Tools absent from state remain stopped by operator choice.

    Returns ``{"repaired": [...], "failed": ["id: why", ...]}``. One tool's failure never
    aborts the rest -- a boot repair should fix what it can and report the remainder, so
    the caller decides what a partial repair means rather than losing it to an exception.
    """
    defs = _all_defs(tools_root, tool_dirs)
    repaired: list[str] = []
    failed: list[str] = []
    for tool_id, record in sorted(_load_state().items()):
        tool_def = defs.get(tool_id)
        if tool_def is None:
            continue  # unregistered since it was started; leave the record for the operator
        running = RunningTool(**record)
        runner = get_runner(running.backend)
        if running.backend == "docker":
            injection_ready = runner.secrets_ready(running)
        else:
            workdir = Path(running.workdir)
            injection_ready = all((workdir / spec.name).is_file() for spec in tool_def.secrets)
        if injection_ready and runner.is_alive(running):
            continue
        try:
            restart(tool_id, tools_root, tool_dirs, secrets_file, backend)
            repaired.append(tool_id)
        except Exception as exc:  # noqa: BLE001 - report every failure, repair the rest
            # restart() removes the old record before starting. Preserve the operator's
            # running intent when start fails so a later reconcile can retry it.
            state = _load_state()
            if tool_id not in state:
                state[tool_id] = record
                _save_state(state)
            failed.append(f"{tool_id}: {exc}")
    return {"repaired": repaired, "failed": failed}


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
