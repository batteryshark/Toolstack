"""Toolyard lifecycle CLI.

    python3 -m toolyard.cli up [id]   --root tools --secrets secrets.toml [--backend process|docker]
    python3 -m toolyard.cli down [id]
    python3 -m toolyard.cli ls

Which tools are running is kept in a small JSON state file so `down`/`ls` work
across invocations.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path

from .config import discover
from .runner import RunningTool, get_runner
from .secrets import get_backend


def _state_path() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(state) / "toolstack" / "toolyard" / "state.json"


def _load_state() -> dict:
    path = _state_path()
    return json.loads(path.read_text()) if path.exists() else {}


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def cmd_up(args) -> None:
    root = args.root or os.environ.get("TOOLSTACK_TOOLS_ROOT") or "tools"
    secrets_file = args.secrets or os.environ.get("TOOLSTACK_SECRETS_FILE") or "secrets.toml"
    defs = {d.id: d for d in discover(root)}
    targets = [args.id] if args.id else list(defs)
    runner = get_runner(args.backend)
    backend = get_backend(args.secret_backend, secrets_file=secrets_file)
    state = _load_state()
    for tool_id in targets:
        if tool_id not in defs:
            raise SystemExit(f"unknown tool: {tool_id}")
        if tool_id in state:
            print(f"{tool_id}: already running")
            continue
        running = runner.start(
            defs[tool_id], backend.resolve(defs[tool_id]),
            secret_backend=args.secret_backend, secrets_file=secrets_file)
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
    parser = argparse.ArgumentParser(prog="toolyard")
    sub = parser.add_subparsers(required=True)

    up = sub.add_parser("up", help="resolve secrets and start one or all tools")
    up.add_argument("id", nargs="?")
    up.add_argument("--root", help="tools root (default: $TOOLSTACK_TOOLS_ROOT or 'tools')")
    up.add_argument("--secrets", help="dev secrets TOML (default: $TOOLSTACK_SECRETS_FILE or 'secrets.toml')")
    up.add_argument("--backend", choices=["process", "docker"],
                    default=os.environ.get("TOOLSTACK_RUNNER", "process"))
    up.add_argument("--secret-backend", choices=["file", "infisical"],
                    default=os.environ.get("TOOLSTACK_SECRET_BACKEND", "file"),
                    help="secret backend (default: $TOOLSTACK_SECRET_BACKEND or 'file')")
    up.set_defaults(func=cmd_up)

    down = sub.add_parser("down", help="stop one or all tools")
    down.add_argument("id", nargs="?")
    down.set_defaults(func=cmd_down)

    ls = sub.add_parser("ls", help="list running tools")
    ls.set_defaults(func=cmd_ls)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
