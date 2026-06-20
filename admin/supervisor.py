"""Supervise the broker process — start, stop, restart, and report its status.

This mirrors ``toolyard/runner.py``'s ``ProcessRunner``: ``os.posix_spawn`` with
``setpgroup=0`` so the broker gets its own process group, then ``os.killpg`` to
stop the whole group. The broker's stdout/stderr are captured to a log file so
"why didn't it start" is answerable, and a ``GET /v1/health`` probe confirms it is
actually serving (not merely a live PID). State (the PID and port) lives in a
small JSON file under the admin state dir.

There is one supervised broker per machine, identified by the state file — the
admin app does not track multiple brokers.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import settings
from .broker_config import BrokerRunConfig

log = logging.getLogger(__name__)


def _is_broker(pid: int) -> bool:
    """Confirm ``pid`` is actually our broker before signalling its process group. The broker is
    supervised out of band, so after the admin app itself restarts it is no longer our child to
    reap — and a bare PID can be reused by an unrelated process. Killing that recycled PID's group
    would be a serious bug, so verify the command line names ``broker.server`` first."""
    try:
        out = subprocess.run(["ps", "-p", str(pid), "-o", "args="],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False  # can't confirm -> treat as 'not the broker' and refuse to signal
    # Match the exact invocation (`… -m broker.server`) as whole argv tokens, not a loose
    # substring — `tail -f broker.server.log` or `-m pkg.broker.server_x` must NOT count.
    try:
        args = shlex.split(out.stdout)
    except ValueError:
        return False
    return any(tok == "-m" and args[i + 1] == "broker.server" for i, tok in enumerate(args[:-1]))


def _state_file() -> Path:
    return settings.state_dir() / "broker.state.json"


def _log_file() -> Path:
    return settings.state_dir() / "broker.log"


def _stopped() -> dict:
    return {"running": False, "pid": None, "port": None, "healthy": None}


def _read_state() -> dict | None:
    path = _state_file()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def _write_state(state: dict) -> None:
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")


def _clear_state() -> None:
    _state_file().unlink(missing_ok=True)


def _pid_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)  # pgid == pid (setpgroup=0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _health(port: int, timeout: float = 0.5) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/v1/health", timeout=timeout
        ) as resp:
            if resp.status != 200:
                return False
            body = json.loads(resp.read() or b"{}")
            return body.get("status") == "ok"
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _await_health(port: int, attempts: int = 40, delay: float = 0.15) -> bool:
    for _ in range(attempts):
        if _health(port):
            return True
        time.sleep(delay)
    return False


def status() -> dict:
    """Report whether the broker is running and healthy. Reaps an exited child and
    clears stale state so a crashed broker never reads as 'running'."""
    state = _read_state()
    if not state:
        return _stopped()
    pid, port = state["pid"], state["port"]
    try:
        reaped, _ = os.waitpid(pid, os.WNOHANG)  # reap if it already exited
        if reaped:
            _clear_state()
            return _stopped()
    except ChildProcessError:
        pass  # not our child (e.g. admin app restarted) — fall through to signal check
    except ProcessLookupError:
        _clear_state()
        return _stopped()
    if not _pid_alive(pid):
        _clear_state()
        return _stopped()
    return {"running": True, "pid": pid, "port": port, "healthy": _health(port)}


def start(config: BrokerRunConfig) -> dict:
    """Start the broker if it is not already running, capturing its output to the
    log file and waiting for it to become healthy. Idempotent."""
    current = status()
    if current["running"]:
        return current
    state_dir = settings.state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **config.to_env()}
    # os.open/os.close (not open()) so the parent leaves no Python file object to
    # warn about; the child keeps its own dup'd copies of fds 1 and 2.
    log_fd = os.open(str(_log_file()), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        pid = os.posix_spawn(
            sys.executable,
            [sys.executable, "-m", "broker.server"],
            env,
            setpgroup=0,
            file_actions=[
                (os.POSIX_SPAWN_DUP2, log_fd, 1),
                (os.POSIX_SPAWN_DUP2, log_fd, 2),
            ],
        )
    finally:
        os.close(log_fd)
    _write_state({"pid": pid, "port": config.port})
    healthy = _await_health(config.port)
    result = status()
    if not healthy and not result.get("healthy"):
        # The process spawned but never answered /v1/health — don't let the caller report a
        # bare success. Surface it (the dashboard/API turn this into an error, not a redirect).
        log.warning("broker pid %s did not become healthy on :%s", pid, config.port)
        result = {**result, "error": (f"broker started (pid {pid}) but did not become healthy "
                                      f"on port {config.port} — check the broker log")}
    return result


def _terminate(pid: int) -> None:
    if not _is_broker(pid):
        # PID reuse after an admin restart: the recorded pid is now some other process. Never
        # signal it — just let the caller clear the stale state.
        log.warning("not terminating pid %s — it is not the broker (stale state / PID reuse)", pid)
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    for _ in range(30):  # up to ~3s for a graceful exit
        try:
            if os.waitpid(pid, os.WNOHANG)[0]:
                return
        except (ChildProcessError, ProcessLookupError):
            return  # not our child, or already gone
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    except (ChildProcessError, ProcessLookupError, PermissionError):
        pass


def stop() -> dict:
    """Stop the broker (SIGTERM, escalating to SIGKILL) and clear its state."""
    state = _read_state()
    if state:
        _terminate(state["pid"])
        _clear_state()
    return _stopped()


def restart(config: BrokerRunConfig) -> dict:
    stop()
    return start(config)


def log_tail(max_bytes: int = 4000) -> str:
    """The tail of the broker's captured stdout/stderr, for the dashboard."""
    path = _log_file()
    if not path.exists():
        return ""
    data = path.read_bytes()[-max_bytes:]
    return data.decode("utf-8", errors="replace")
