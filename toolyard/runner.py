"""Tool runners.

`ProcessRunner` (dev/CI, zero infra) starts the tool as a local subprocess with
its secrets written to a private 0700 dir, pointed at by `$TOOLSTACK_SECRETS_DIR`.
`DockerRunner` (production) runs the tool in a container with its secrets mounted
at `/run/secrets`. Both keep secret values entirely off the broker.

On stop, the secrets dir is removed; if `start` fails partway it cleans up the
(world-readable) secrets dir and any write-proxy it spawned, so a failed start never
leaks secret material on disk or orphans the proxy. Docker subprocess calls carry
timeouts so a wedged daemon can't hang the caller (start/stop runs inside an admin
request). (Hardening note: production should inject secrets into a container tmpfs at
start so they never touch host disk; the bind mount here is the simpler form.)
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .config import ToolDef

# Container-internal mount point for the writable-secret socket (message-contracts
# §4); matches the tool's default TOOLYARD_SECRETS_SOCKET.
_CONTAINER_SOCKET = "/run/toolyard/secrets.sock"
_CONTAINER_TOOL_CONFIG = "/run/toolstack/toolyard.toml"
_REPO_ROOT = Path(__file__).resolve().parents[1]  # so `-m toolyard.write_proxy` imports

# Docker subprocess timeouts (seconds): a slow pull or a wedged daemon must fail with a
# clear error, not hang the calling thread (toolyard start/stop runs in an admin request).
_DOCKER_BUILD_TIMEOUT = 600
_DOCKER_RUN_TIMEOUT = 60
_DOCKER_RM_TIMEOUT = 30
_DOCKER_INSPECT_TIMEOUT = 10
# How long start() waits before confirming a process tool didn't immediately exit.
_READINESS_WAIT = 0.3

log = logging.getLogger(__name__)


def _tool_log_path(tool_id: str) -> Path:
    """Per-tool logfile under the state dir, so a tool's stdout/stderr can be tailed to
    diagnose a failed start or a crash (the process runner dup's the child onto it)."""
    state = Path(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"))
    d = state / "toolstack" / "tools"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{tool_id}.log"


def _check_port_free(port: int) -> None:
    """Fail early + clearly if the tool's loopback port is already taken; otherwise the tool
    binds, exits, and only surfaces as a 502 at call time."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
    except OSError as exc:
        raise RuntimeError(f"127.0.0.1:{port} is not available for tool start: {exc}") from exc
    finally:
        s.close()


def _cleanup_partial_start(secrets_dir: str, proxy_pid: str | None, proxy_dir: str | None,
                           child_pid: int | None = None) -> None:
    """Best-effort cleanup when start() fails partway: never leave the (world-readable) secrets
    dir on disk, an orphaned write-proxy, or an unreaped child zombie behind. start() runs inside
    the long-lived admin handler, so a leaked zombie per failed start would accrue there; kill
    AND reap both the tool child and the proxy (a readiness-failed child is already a zombie)."""
    for pid in (child_pid, proxy_pid):
        if pid is None:
            continue
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError):
            pass
        try:
            os.waitpid(int(pid), 0)
        except (ChildProcessError, ProcessLookupError, ValueError):
            pass
    if proxy_dir:
        shutil.rmtree(proxy_dir, ignore_errors=True)
    shutil.rmtree(secrets_dir, ignore_errors=True)


@dataclass(frozen=True)
class RunningTool:
    tool_id: str
    port: int
    backend: str
    handle: str  # pid (process) or container name (docker)
    workdir: str  # secrets dir to clean up on stop
    proxy_pid: str | None = None  # writable-secret proxy pid (when the tool has one)
    proxy_dir: str | None = None  # proxy socket dir to clean up on stop


def _write_secrets(tool_id: str, secrets: dict[str, str]) -> str:
    secrets_dir = tempfile.mkdtemp(prefix=f"toolyard-{tool_id}-")
    try:
        for name, value in secrets.items():
            path = Path(secrets_dir) / name
            path.write_text(value, encoding="utf-8")
            path.chmod(0o600)
    except BaseException:  # a mid-loop failure must not leave a half-written secrets dir on disk
        shutil.rmtree(secrets_dir, ignore_errors=True)
        raise
    return secrets_dir


def _start_write_proxy(tool_def: ToolDef, secret_backend: str | None,
                       secrets_file: str | None) -> tuple[str | None, str | None]:
    """Start the writable-secret proxy for tools that declare a writable field.

    Returns (proxy_pid, proxy_dir), or (None, None) when there is nothing to write.
    The proxy runs on the host (holding the backend); only its socket is exposed to
    the tool. It is spawned detached in its own process group so stop() can kill it.
    """
    if not any(s.writable for s in tool_def.secrets):
        return None, None
    proxy_dir = tempfile.mkdtemp(prefix=f"toolyard-sock-{tool_def.id}-")
    os.chmod(proxy_dir, 0o711)  # let the (non-root) container user traverse to the socket
    socket_path = str(Path(proxy_dir) / "secrets.sock")
    backend = secret_backend or os.environ.get("TOOLSTACK_SECRET_BACKEND", "file")
    cmd = (
        f"exec {shlex.quote(sys.executable)} -m toolyard.write_proxy "
        f"--socket {shlex.quote(socket_path)} "
        f"--toml {shlex.quote(str(tool_def.path / 'toolyard.toml'))} "
        f"--secret-backend {shlex.quote(backend)}"
    )
    if secrets_file:
        cmd += f" --secrets-file {shlex.quote(secrets_file)}"
    script = f"cd {shlex.quote(str(_REPO_ROOT))} && {cmd}"
    pid = os.posix_spawn("/bin/sh", ["/bin/sh", "-c", script], os.environ, setpgroup=0)
    return str(pid), proxy_dir


def _stop_proxy(running: RunningTool) -> None:
    if running.proxy_pid:
        try:
            os.killpg(int(running.proxy_pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError):
            pass
        try:
            os.waitpid(int(running.proxy_pid), 0)
        except (ChildProcessError, ProcessLookupError, ValueError):
            pass
    if running.proxy_dir:
        shutil.rmtree(running.proxy_dir, ignore_errors=True)


class ProcessRunner:
    backend = "process"

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = None, secrets_file: str | None = None) -> RunningTool:
        if not tool_def.command:
            raise ValueError(f"tool {tool_def.id} has no entrypoint.command")
        _check_port_free(tool_def.port)
        secrets_dir = _write_secrets(tool_def.id, secrets)
        proxy_pid = proxy_dir = None
        child_pid = None
        try:
            proxy_pid, proxy_dir = _start_write_proxy(tool_def, secret_backend, secrets_file)
            env = {
                **os.environ,
                "TOOLSTACK_SECRETS_DIR": secrets_dir,
                "TOOLSTACK_PORT": str(tool_def.port),
                "TOOLSTACK_TOOL_CONFIG": str(tool_def.path / "toolyard.toml"),
            }
            if proxy_dir:
                env["TOOLYARD_SECRETS_SOCKET"] = str(Path(proxy_dir) / "secrets.sock")
            # posix_spawn (not Popen) so the detached child has no lifecycle object to
            # warn about; setpgroup=0 gives it its own group so stop() can killpg it.
            script = f"cd {shlex.quote(str(tool_def.path))} && exec {tool_def.command}"
            # Capture the tool's stdout/stderr onto a per-tool logfile (the child's fd 1/2) so a
            # crash or a noisy start is diagnosable, not lost into the toolyard's own stream.
            log_path = _tool_log_path(tool_def.id)
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                pid = os.posix_spawn(
                    "/bin/sh", ["/bin/sh", "-c", script], env, setpgroup=0,
                    file_actions=[(os.POSIX_SPAWN_DUP2, log_fd, 1),
                                  (os.POSIX_SPAWN_DUP2, log_fd, 2),
                                  (os.POSIX_SPAWN_CLOSE, log_fd)],
                )
            finally:
                os.close(log_fd)
            child_pid = pid  # track so a readiness failure (below) reaps it, not just kills it
            running = RunningTool(tool_def.id, tool_def.port, self.backend, str(pid), secrets_dir,
                                  proxy_pid, proxy_dir)
            # Readiness: a bad command (missing file, import error) execs and exits at once.
            # Catch it now (with the logfile to diagnose) instead of recording a phantom
            # "running" tool that 502s every call.
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} exited immediately on start: see {log_path}")
            log.info("started tool %s on 127.0.0.1:%s (pid %s, log %s)",
                     tool_def.id, tool_def.port, pid, log_path)
            return running
        except BaseException:
            _cleanup_partial_start(secrets_dir, proxy_pid, proxy_dir, child_pid)
            raise

    def stop(self, running: RunningTool) -> None:
        pid = int(running.handle)
        try:
            os.killpg(pid, signal.SIGTERM)  # pgid == pid (setpgroup=0)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            os.waitpid(pid, 0)  # reap if it is our child (no-op across processes)
        except (ChildProcessError, ProcessLookupError):
            pass
        _stop_proxy(running)
        shutil.rmtree(running.workdir, ignore_errors=True)
        log.info("stopped tool %s (pid %s)", running.tool_id, running.handle)

    def is_alive(self, running: RunningTool) -> bool:
        try:
            os.killpg(int(running.handle), 0)
            return True
        except (ProcessLookupError, PermissionError):
            # PermissionError==dead is load-bearing for the start() readiness check: on Darwin a
            # just-exited (zombie) process-group leader answers killpg(pid, 0) with EPERM, not ESRCH.
            return False


class DockerRunner:
    backend = "docker"

    @staticmethod
    def _docker(args: list[str], timeout: float, *, check: bool = False) -> subprocess.CompletedProcess:
        """Run `docker <args>` with a timeout; map a hang or a non-zero exit to a clear
        RuntimeError (so a wedged daemon never blocks the caller indefinitely)."""
        try:
            return subprocess.run(["docker", *args], capture_output=True, text=True,
                                  check=check, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"docker {args[0]} timed out after {timeout:.0f}s") from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"docker {args[0]} failed: {(exc.stderr or '').strip() or exc}") from exc

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = None, secrets_file: str | None = None) -> RunningTool:
        secrets_dir = _write_secrets(tool_def.id, secrets)
        proxy_pid = proxy_dir = None
        name = None
        try:
            # The bind mount exposes host files by uid; a tool image that drops to a
            # non-root user (the recommended posture) cannot read files owned by the
            # runner's uid under a 0700 dir. Relax to "traverse + read by name" so the
            # container user can read its secrets, while the parent /tmp dir keeps the
            # values off shared paths. (Hardening note: a tmpfs injection at container
            # start removes the host-disk hop entirely.)
            os.chmod(secrets_dir, 0o711)
            for path in Path(secrets_dir).iterdir():
                path.chmod(0o644)
            proxy_pid, proxy_dir = _start_write_proxy(tool_def, secret_backend, secrets_file)
            rest_generic = tool_def.type == "rest" and tool_def.image is None
            image = tool_def.image or ("python:3.13-slim" if rest_generic else f"toolstack-{tool_def.id}")
            if tool_def.image is None and not rest_generic:
                self._docker(["build", "-t", image, str(tool_def.path)], _DOCKER_BUILD_TIMEOUT, check=True)
            name = f"toolyard-{tool_def.id}"
            self._docker(["rm", "-f", name], _DOCKER_RM_TIMEOUT)  # clear a same-named leftover
            run_args = [
                "run", "-d", "--name", name,
                "-p", f"127.0.0.1:{tool_def.port}:{tool_def.port}",
                "-e", f"TOOLSTACK_PORT={tool_def.port}",
                "-e", "TOOLSTACK_BIND=0.0.0.0",  # container-internal; host side stays loopback via -p
                "-v", f"{secrets_dir}:/run/secrets:ro",
            ]
            if tool_def.type == "rest":
                run_args += [
                    "-v", f"{tool_def.path / 'toolyard.toml'}:{_CONTAINER_TOOL_CONFIG}:ro",
                    "-e", f"TOOLSTACK_TOOL_CONFIG={_CONTAINER_TOOL_CONFIG}",
                ]
                if rest_generic:
                    run_args += [
                        "-v", f"{_REPO_ROOT}:/app:ro",
                        "-w", "/app",
                    ]
            if proxy_dir:
                # Mount the proxy's socket dir so the tool reaches it at the contract path.
                run_args += ["-v", f"{proxy_dir}:/run/toolyard",
                             "-e", f"TOOLYARD_SECRETS_SOCKET={_CONTAINER_SOCKET}"]
            run_args.append(image)
            if rest_generic:
                run_args += ["python3", "-m", "toolstack_forwarder"]
            self._docker(run_args, _DOCKER_RUN_TIMEOUT, check=True)
            running = RunningTool(tool_def.id, tool_def.port, self.backend, name, secrets_dir,
                                  proxy_pid, proxy_dir)
            # Readiness: a container that exits at once (bad image / port clash) must not record
            # as running, then 502 every call. Settle briefly first: `docker run -d` returns at
            # create, so an immediate crash can still read Running=true for a moment.
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} container exited immediately: docker logs {name}")
            log.info("started tool %s in container %s on :%s (docker logs %s)",
                     tool_def.id, name, tool_def.port, name)
            return running
        except BaseException:
            if name:  # drop the just-created (now-stopped) container so a failed start isn't litter
                try:
                    subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                                   timeout=_DOCKER_RM_TIMEOUT)
                except subprocess.TimeoutExpired:
                    pass
            _cleanup_partial_start(secrets_dir, proxy_pid, proxy_dir)
            raise

    def stop(self, running: RunningTool) -> None:
        try:
            r = subprocess.run(["docker", "rm", "-f", running.handle],
                               capture_output=True, text=True, timeout=_DOCKER_RM_TIMEOUT)
            if r.returncode != 0:
                # The caller clears the state record after stop(); surface the leftover so an
                # operator can `docker rm` it (the next start's `rm -f` also clears it by name).
                log.warning("docker rm %s failed on stop (rc=%s): %s; container may still exist",
                            running.handle, r.returncode, (r.stderr or "").strip())
        except subprocess.TimeoutExpired:
            log.warning("docker rm %s timed out on stop; container may still exist", running.handle)
        _stop_proxy(running)
        shutil.rmtree(running.workdir, ignore_errors=True)
        log.info("stopped tool %s (container %s)", running.tool_id, running.handle)

    def is_alive(self, running: RunningTool) -> bool:
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", running.handle],
                capture_output=True, text=True, timeout=_DOCKER_INSPECT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log.warning("docker inspect %s timed out", running.handle)
            return False
        return result.stdout.strip() == "true"


def get_runner(backend: str):
    if backend == "process":
        return ProcessRunner()
    if backend == "docker":
        return DockerRunner()
    raise ValueError(f"unknown runner backend: {backend}")
