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
import fcntl
import tempfile
import stat
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .config import discover
from .runner import RunningTool, RunnerStartCleanupError, get_runner


def _state_path() -> Path:
    explicit = os.environ.get("TOOLSTACK_TOOLYARD_STATE")
    if explicit:
        return Path(explicit)
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(state) / "toolstack" / "toolyard" / "state.json"


def _load_state() -> dict:
    path = _state_path()
    _private_parent(path)
    _validate_file(path)
    return json.loads(path.read_text()) if path.exists() else {}


def _private_parent(path: Path) -> None:
    """Create private directories, but never repair arbitrary existing permissions.

    Refuse symlinks anywhere in the parent chain; existing leaf directories must
    already be owned by us and private. Shared ancestors (e.g. /tmp) aren't chmodded.
    Same-owner hostile processes remain outside this trusted-host threat model.
    """
    parent = path.absolute().parent
    for ancestor in reversed((parent, *parent.parents)):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            ancestor.mkdir(mode=0o700, exist_ok=True)
            info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"unsafe state directory: {ancestor}")
    info = parent.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"state directory must be owner-private: {parent}")


def _validate_file(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
        raise ValueError(f"state file must be private, regular and unlinked: {path}")


def _save_state(state: dict) -> None:
    """Publish private state then the credential-only view; caller holds state_lock."""
    path = _state_path()
    channel_path = Path(os.environ.get("TOOLSTACK_TOOLYARD_CHANNEL_STATE",
                                       str(path.with_name("channels.json"))))
    destinations = [os.path.abspath(p) for p in (path, channel_path, path.with_suffix(".lock"))]
    if len(set(destinations)) != len(destinations):
        raise ValueError("private state, channel view and lock must have different paths")
    for target in (path, channel_path):
        _private_parent(target)
        _validate_file(target)
    _atomic_private_json(path, state)
    channels = {key: {"channel_secret": rec["channel_secret"]}
                for key, rec in state.items() if rec.get("channel_secret")}
    _atomic_private_json(channel_path, channels)


def _atomic_private_json(path: Path, value: dict) -> None:
    _private_parent(path)
    _validate_file(path)
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def state_lock():
    """Hold across the entire load / lifecycle / save transaction, not just rename."""
    path = _state_path()
    if path.with_suffix(".lock") == path:
        raise ValueError("private state path must differ from lock path")
    _private_parent(path)
    _validate_file(path.with_suffix(".lock"))
    fd = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _locked(fn):
    def call(*args, **kwargs):
        with state_lock():
            return fn(*args, **kwargs)
    return call


@_locked
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
            try:
                recorded_runner.stop(recorded)
            except RunnerStartCleanupError as exc:
                state[tool_id] = asdict(exc.running)
                _save_state(state)
                raise
            del state[tool_id]
            # Persist the cleanup before starting. If start fails, the dead record must
            # not make every later `up` look successful while doing nothing.
            _save_state(state)
        try:
            running = runner.start(defs[tool_id])
        except RunnerStartCleanupError as exc:
            state[tool_id] = asdict(exc.running)
            _save_state(state)
            raise
        state[tool_id] = asdict(running)
        try:
            _save_state(state)
        except Exception:
            runner.stop(running)
            del state[tool_id]
            _save_state(state)
            raise
        print(f"{tool_id}: started ({running.backend}) on 127.0.0.1:{running.port}")
    _save_state(state)


@_locked
def cmd_down(args) -> None:
    state = _load_state()
    targets = [args.id] if args.id else list(state)
    for tool_id in targets:
        if tool_id not in state:
            print(f"{tool_id}: not running")
            continue
        running = RunningTool(**state[tool_id])
        try:
            get_runner(running.backend).stop(running)
        except RunnerStartCleanupError as exc:
            state[tool_id] = asdict(exc.running)
            _save_state(state)
            raise
        del state[tool_id]
        _save_state(state)
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
