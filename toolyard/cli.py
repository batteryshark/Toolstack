"""Toolyard lifecycle CLI.

    python3 -m toolyard.cli up [id]   --root tools [--backend process|docker]
    python3 -m toolyard.cli down [id]
    python3 -m toolyard.cli ls

Which tools are running is kept in a small JSON state file so `down`/`ls` work
across invocations. Tools fetch their secrets from SPS at boot; the runner
mints the per-tool E_SECRET and registers the tool with SPS on start.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path

from .config import discover
from .runner import RunningTool, get_runner


def _state_path() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(state) / "toolstack" / "toolyard" / "state.json"


def _load_state() -> dict:
    path = _state_path()
    return json.loads(path.read_text()) if path.exists() else {}


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, path)   # atomic: a torn write can't orphan the running tools' records


def cmd_up(args) -> None:
    root = args.root or os.environ.get("TOOLSTACK_TOOLS_ROOT") or "tools"
    defs = {d.id: d for d in discover(root)}
    targets = [args.id] if args.id else list(defs)
    runner = get_runner(args.backend)
    state = _load_state()
    for tool_id in targets:
        if tool_id not in defs:
            raise SystemExit(f"unknown tool: {tool_id}")
        if tool_id in state:
            recorded = RunningTool(**state[tool_id])
            recorded_runner = get_runner(recorded.backend)
            if recorded_runner.is_alive(recorded):
                print(f"{tool_id}: already running")
                continue
            recorded_runner.stop(recorded)
            del state[tool_id]
            # Persist the cleanup before starting. If start fails, the dead record must
            # not make every later `up` look successful while doing nothing.
            _save_state(state)
        running = runner.start(defs[tool_id])
        state[tool_id] = asdict(running)
        print(f"{tool_id}: started ({running.backend}) on 127.0.0.1:{running.port}")
    _save_state(state)


def cmd_down(args) -> None:
    state = _load_state()
    targets = [args.id] if args.id else list(state)
    for tool_id in targets:
        if tool_id not in state:
            print(f"{tool_id}: not running")
            continue
        running = RunningTool(**state[tool_id])
        get_runner(running.backend).stop(running)
        del state[tool_id]
        print(f"{tool_id}: stopped")
    _save_state(state)


def cmd_reload(args) -> None:
    cmd_down(args)
    cmd_up(args)


def cmd_ls(args) -> None:
    state = _load_state()
    if not state:
        print("no tools running")
        return
    for tool_id, record in state.items():
        running = RunningTool(**record)
        alive = "alive" if get_runner(running.backend).is_alive(running) else "dead"
        print(f"{tool_id}\t{running.backend}\t127.0.0.1:{running.port}\t{alive}")


def main() -> None:
    logging.basicConfig(level=os.environ.get("TOOLSTACK_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="toolyard")
    sub = parser.add_subparsers(required=True)

    up = sub.add_parser("up", help="start one or all tools (secrets come from SPS)")
    up.add_argument("id", nargs="?")
    up.add_argument("--root", help="tools root (default: $TOOLSTACK_TOOLS_ROOT or 'tools')")
    up.add_argument("--backend", choices=["process", "docker"],
                    default=os.environ.get("TOOLSTACK_RUNNER", "process"))
    up.set_defaults(func=cmd_up)

    down = sub.add_parser("down", help="stop one or all tools")
    down.add_argument("id", nargs="?")
    down.set_defaults(func=cmd_down)

    reload_p = sub.add_parser("reload", help="restart one or all tools")
    reload_p.add_argument("id", nargs="?")
    reload_p.add_argument("--root", help="tools root (default: $TOOLSTACK_TOOLS_ROOT or 'tools')")
    reload_p.add_argument("--backend", choices=["process", "docker"],
                          default=os.environ.get("TOOLSTACK_RUNNER", "process"))
    reload_p.set_defaults(func=cmd_reload)

    ls = sub.add_parser("ls", help="list running tools")
    ls.set_defaults(func=cmd_ls)

    args = parser.parse_args()
    try:
        args.func(args)
    except ValueError as exc:
        # a malformed toolyard.toml (e.g. a missing/invalid port) -> a clean one-line
        # message and a non-zero exit, not a traceback.
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
