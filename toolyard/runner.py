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
import re
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
from typing import Protocol

from .config import ToolDef
from .sandbox import EgressPolicy, ResourceCaps, SandboxPolicy

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


def _tool_log_path(tool_def: ToolDef) -> Path:
    """Per-tool logfile in the tool folder (`logs/tool.log`) so tool output travels with
    the tool, not an opaque global state directory."""
    d = tool_def.path / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d / "tool.log"


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


def _terminate(pid: str | int | None) -> None:
    """SIGTERM a detached process group (a setpgroup=0 leader) and reap it; best-effort.
    Shared by the write proxy, the egress proxy, the log follower, and start()'s cleanup."""
    if pid is None:
        return
    try:
        os.killpg(int(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, ValueError):
        pass
    try:
        os.waitpid(int(pid), 0)
    except (ChildProcessError, ProcessLookupError, ValueError):
        pass


def _cleanup_partial_start(secrets_dir: str, proxy_pid: str | None, proxy_dir: str | None,
                           child_pid: int | None = None, log_pid: str | None = None,
                           egress_pid: str | None = None) -> None:
    """Best-effort cleanup when start() fails partway: never leave the (world-readable) secrets
    dir on disk, an orphaned write/egress proxy, or an unreaped child zombie behind. start() runs
    inside the long-lived admin handler, so a leaked zombie per failed start would accrue there;
    kill AND reap the tool child and both proxies (a readiness-failed child is already a zombie)."""
    for pid in (child_pid, proxy_pid, log_pid, egress_pid):
        _terminate(pid)
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
    log_pid: str | None = None  # docker log follower pid (process runner logs directly)
    log_path: str | None = None
    egress_pid: str | None = None  # per-tool egress proxy pid (tools with an egress allowlist)


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


def _pick_free_port() -> int:
    """An ephemeral loopback port for a per-tool helper (the egress proxy). Small TOCTOU
    window between pick and the proxy's bind; a lost race just fails the start loudly."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _start_egress_proxy(allow: tuple[str, ...]) -> tuple[str, int]:
    """Start the per-tool egress proxy on a loopback port and return (pid, port). The tool's
    HTTP(S)_PROXY is pointed here and the sandbox permits outbound only to this port, so the
    proxy is the single exit and enforces the host allowlist. Detached in its own group so
    stop() can kill it, exactly like the write proxy."""
    port = _pick_free_port()
    allow_args = " ".join(f"--allow {shlex.quote(h)}" for h in allow)
    cmd = (f"exec {shlex.quote(sys.executable)} -m toolyard.egress_proxy "
           f"--port {port} {allow_args}")
    script = f"cd {shlex.quote(str(_REPO_ROOT))} && {cmd}"
    pid = os.posix_spawn("/bin/sh", ["/bin/sh", "-c", script], os.environ, setpgroup=0)
    return str(pid), port


def _stop_proxy(running: RunningTool) -> None:
    _terminate(running.proxy_pid)
    if running.proxy_dir:
        shutil.rmtree(running.proxy_dir, ignore_errors=True)


def _stop_log_follower(running: RunningTool) -> None:
    _terminate(running.log_pid)


def _stop_egress_proxy(running: RunningTool) -> None:
    _terminate(running.egress_pid)


def _start_docker_log_follower(container: str, log_path: Path) -> str:
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        pid = os.posix_spawn(
            "/usr/bin/env",
            ["env", "docker", "logs", "-f", container],
            os.environ,
            setpgroup=0,
            file_actions=[(os.POSIX_SPAWN_DUP2, fd, 1),
                          (os.POSIX_SPAWN_DUP2, fd, 2),
                          (os.POSIX_SPAWN_CLOSE, fd)],
        )
    finally:
        os.close(fd)
    return str(pid)


# A bare Python interpreter token: `python`, `python3`, `python3.13` — but not a path
# (`/usr/bin/python3`, `./python`) and not another program.
_PY_INTERPRETER = re.compile(r"python(\d+(\.\d+)?)?")


def _bind_interpreter(command: str) -> str:
    """Rebind a leading bare ``python``/``python3`` token to this process's own interpreter
    (``sys.executable``) so a process-backend tool runs under the same Python — and the same
    virtualenv — as the broker that spawns it.

    The generic REST forwarder ships ``command = "python3 -m toolstack_forwarder"``. On a host
    whose PATH ``python3`` is the system interpreter, that module isn't importable and the tool
    exits immediately with ModuleNotFoundError. Binding to ``sys.executable`` fixes this without
    hardcoding a venv path, so it stays portable across install locations. A command that names
    an explicit path (``/usr/bin/python3``, ``./run.sh``) or a different program (``node ...``)
    is left untouched — an explicit interpreter is the author's deliberate choice. The rest of
    the command is preserved verbatim (only the interpreter token is swapped)."""
    parts = command.split(None, 1)
    if not parts or "/" in parts[0] or not _PY_INTERPRETER.fullmatch(parts[0]):
        return command
    rest = parts[1] if len(parts) > 1 else ""
    return f"{shlex.quote(sys.executable)} {rest}".rstrip()


class Runner(Protocol):
    """The runner contract every backend satisfies: a `backend` tag plus start / stop /
    is_alive over a `RunningTool`. `get_runner` returns one of these. ProcessRunner and
    DockerRunner implement it structurally (no inheritance needed), and the coming native
    sandbox runners will too -- this names the seam they all build against."""

    backend: str

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = ..., secrets_file: str | None = ...) -> RunningTool: ...

    def stop(self, running: RunningTool) -> None: ...

    def is_alive(self, running: RunningTool) -> bool: ...


class ProcessRunner:
    backend = "process"

    def _policy(self, tool_def: ToolDef) -> SandboxPolicy:
        """The sandbox policy this backend enforces for a tool. ProcessRunner enforces
        nothing (no isolation), so it returns the safe default and never starts an egress
        proxy even if the tool declares one -- egress is only meaningful under a sandbox.
        SeatbeltRunner overrides this to read the tool's declared egress allowlist."""
        return SandboxPolicy()

    def _spawn_argv(self, tool_def: ToolDef, inner_script: str, proxy_dir: str | None,
                    egress_port: int | None) -> tuple[str, list[str]]:
        """Executable + argv to posix_spawn for the tool. ProcessRunner runs it under a
        bare shell; SeatbeltRunner overrides this to wrap the same launch in sandbox-exec.
        This is the single point of variation between the two process-based backends."""
        return "/bin/sh", ["/bin/sh", "-c", inner_script]

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = None, secrets_file: str | None = None) -> RunningTool:
        if not tool_def.command:
            raise ValueError(f"tool {tool_def.id} has no entrypoint.command")
        _check_port_free(tool_def.port)
        secrets_dir = _write_secrets(tool_def.id, secrets)
        proxy_pid = proxy_dir = None
        egress_pid = egress_port = None
        child_pid = None
        log_path = _tool_log_path(tool_def)
        try:
            proxy_pid, proxy_dir = _start_write_proxy(tool_def, secret_backend, secrets_file)
            policy = self._policy(tool_def)
            if policy.egress.allow:
                egress_pid, egress_port = _start_egress_proxy(policy.egress.allow)
            env = {
                **os.environ,
                "TOOLSTACK_SECRETS_DIR": secrets_dir,
                "TOOLSTACK_PORT": str(tool_def.port),
                "TOOLSTACK_TOOL_CONFIG": str(tool_def.path / "toolyard.toml"),
            }
            if proxy_dir:
                env["TOOLYARD_SECRETS_SOCKET"] = str(Path(proxy_dir) / "secrets.sock")
            if egress_port:
                # Route the tool's outbound HTTP(S) through its egress proxy; the sandbox
                # allows outbound only to this port, so the proxy is the sole exit.
                proxy_url = f"http://127.0.0.1:{egress_port}"
                for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                    env[var] = proxy_url
            # posix_spawn (not Popen) so the detached child has no lifecycle object to
            # warn about; setpgroup=0 gives it its own group so stop() can killpg it.
            inner_script = f"cd {shlex.quote(str(tool_def.path))} && exec {_bind_interpreter(tool_def.command)}"
            executable, argv = self._spawn_argv(tool_def, inner_script, proxy_dir, egress_port)
            # Capture the tool's stdout/stderr onto a per-tool logfile (the child's fd 1/2) so a
            # crash or a noisy start is diagnosable, not lost into the toolyard's own stream.
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                pid = os.posix_spawn(
                    executable, argv, env, setpgroup=0,
                    file_actions=[(os.POSIX_SPAWN_DUP2, log_fd, 1),
                                  (os.POSIX_SPAWN_DUP2, log_fd, 2),
                                  (os.POSIX_SPAWN_CLOSE, log_fd)],
                )
            finally:
                os.close(log_fd)
            child_pid = pid  # track so a readiness failure (below) reaps it, not just kills it
            running = RunningTool(tool_def.id, tool_def.port, self.backend, str(pid), secrets_dir,
                                  proxy_pid, proxy_dir, log_path=str(log_path), egress_pid=egress_pid)
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
            _cleanup_partial_start(secrets_dir, proxy_pid, proxy_dir, child_pid, egress_pid=egress_pid)
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
        _stop_log_follower(running)
        _stop_egress_proxy(running)
        shutil.rmtree(running.workdir, ignore_errors=True)
        log.info("stopped tool %s (pid %s)", running.tool_id, running.handle)

    def is_alive(self, running: RunningTool) -> bool:
        pid = int(running.handle)
        # Reap-aware liveness. The tool is our own posix_spawn child, so poll it with waitpid
        # first: on Linux a just-exited child that has not been reaped is a zombie whose pid still
        # answers killpg(pid, 0) as "alive", which would let start()'s readiness check pass a tool
        # that already crashed. waitpid(WNOHANG) reports (and reaps) the exit; (0, 0) means it is
        # still running. ChildProcessError means it is not ours to reap (already reaped, or a
        # handle carried across processes) -- fall back to the signal probe below.
        try:
            reaped, _ = os.waitpid(pid, os.WNOHANG)
            if reaped:
                return False
        except ChildProcessError:
            pass
        try:
            os.killpg(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            # On macOS a just-exited (zombie) group leader answers killpg with EPERM, not ESRCH;
            # both mean dead here. (Linux's zombie case is caught by the waitpid poll above.)
            return False


_SANDBOX_EXEC = "/usr/bin/sandbox-exec"  # macOS Seatbelt wrapper


def _seatbelt_profile(policy: SandboxPolicy, *, allow_unix_egress: bool,
                      egress_port: int | None = None) -> str:
    """Render an SBPL profile (macOS Seatbelt) for one tool from its SandboxPolicy.

    Baseline: let the process run normally (read files, fork, exec) but cut all network,
    then re-open exactly what a loopback-served tool needs -- bind + accept on localhost so
    the broker can reach it. Arbitrary outbound stays denied, which is the isolation the
    process and (as configured) docker runners don't provide. Filesystem-write confinement
    and a read-path allowlist are a later tightening; this profile confines the network.

    When the tool has an egress allowlist, outbound is re-opened only to its egress proxy on
    `egress_port` -- the rule is port-scoped (verified on macOS 26: it does not leak to other
    loopback ports), so the tool reaches the proxy and nothing else, and the proxy enforces
    the host allowlist. `allow_unix_egress` re-opens unix-socket egress for the writable-secret
    proxy; macOS 26 SBPL does not honour a path filter on unix-socket, so it is broad and thus
    emitted only for a tool that actually has a proxy (no writable secrets -> no unix egress)."""
    if policy.egress.allow and egress_port is None:
        raise ValueError("egress allowlist requires an egress proxy port (runner bug)")
    if policy.resources != ResourceCaps():
        # There is no cgroups on macOS; Seatbelt cannot cap memory/cpu/pids. Say so rather
        # than drop the caps silently -- a hard cap on macOS is the microVM tier's job.
        log.warning("resource caps are not enforced by the macOS Seatbelt runner "
                    "(use the Linux backend or the microVM tier): %s", policy.resources)
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        '(allow network-bind (local ip "localhost:*"))',
        '(allow network-inbound (local ip "localhost:*"))',
    ]
    if policy.egress.allow:
        lines.append(f'(allow network-outbound (remote ip "localhost:{egress_port}"))')
    if allow_unix_egress:
        lines.append("(allow network-outbound (remote unix-socket))")
    return "\n".join(lines) + "\n"


class SeatbeltRunner(ProcessRunner):
    """macOS-native tool sandbox: the same process model as ProcessRunner, but the launch is
    wrapped in `sandbox-exec` with a per-tool Seatbelt profile so the tool cannot open
    arbitrary outbound network connections. No container runtime, no VM. start/stop/is_alive
    are inherited unchanged -- the handle is the pid, exactly as for the process backend."""

    backend = "seatbelt"

    def _policy(self, tool_def: ToolDef) -> SandboxPolicy:
        # Read the tool's declared egress allowlist; resource caps are not derived from the
        # toml yet (and macOS can't enforce them anyway -- see _seatbelt_profile).
        return SandboxPolicy(egress=EgressPolicy(allow=tuple(tool_def.egress)))

    def _spawn_argv(self, tool_def: ToolDef, inner_script: str, proxy_dir: str | None,
                    egress_port: int | None) -> tuple[str, list[str]]:
        # sandbox-exec applies the profile then execs the shell, which execs the tool, so the
        # pid we get back is the tool -- pgroup kill/reap is unchanged from the process backend.
        profile = _seatbelt_profile(self._policy(tool_def),
                                    allow_unix_egress=proxy_dir is not None, egress_port=egress_port)
        return _SANDBOX_EXEC, ["sandbox-exec", "-p", profile, "/bin/sh", "-c", inner_script]


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
        log_pid = None
        log_path = _tool_log_path(tool_def)
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
            log_pid = _start_docker_log_follower(name, log_path)
            running = RunningTool(tool_def.id, tool_def.port, self.backend, name, secrets_dir,
                                  proxy_pid, proxy_dir, log_pid=log_pid, log_path=str(log_path))
            # Readiness: a container that exits at once (bad image / port clash) must not record
            # as running, then 502 every call. Settle briefly first: `docker run -d` returns at
            # create, so an immediate crash can still read Running=true for a moment.
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} container exited immediately: see {log_path}")
            log.info("started tool %s in container %s on :%s (log %s)",
                     tool_def.id, name, tool_def.port, log_path)
            return running
        except BaseException:
            if name:  # drop the just-created (now-stopped) container so a failed start isn't litter
                try:
                    subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                                   timeout=_DOCKER_RM_TIMEOUT)
                except subprocess.TimeoutExpired:
                    pass
            _cleanup_partial_start(secrets_dir, proxy_pid, proxy_dir, log_pid=log_pid)
            raise

    def stop(self, running: RunningTool) -> None:
        _stop_log_follower(running)
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


def native_backend(platform: str | None = None) -> str:
    """The OS-native sandbox backend for this platform: `seatbelt` on macOS, `bwrap`
    (bubblewrap + Landlock + seccomp) on Linux. Windows is out of scope. Split out from
    get_runner so the platform mapping is testable without the runner classes existing."""
    plat = platform if platform is not None else sys.platform
    if plat == "darwin":
        return "seatbelt"
    if plat.startswith("linux"):
        return "bwrap"
    raise RuntimeError(f"no native tool sandbox for platform {plat!r} (macOS and Linux only)")


def get_runner(backend: str) -> Runner:
    if backend == "process":
        return ProcessRunner()
    if backend == "docker":
        return DockerRunner()
    # OS-native sandbox backends. "sandbox" resolves to the right one for this host.
    if backend == "sandbox":
        backend = native_backend()
    if backend == "seatbelt":
        return SeatbeltRunner()
    if backend == "bwrap":
        # The Linux backend (bubblewrap + Landlock + seccomp) lands next on this branch.
        raise NotImplementedError(
            "the 'bwrap' (Linux) sandbox runner is not implemented yet "
            "(native-sandbox-runner branch); use 'process' or 'docker' for now")
    raise ValueError(f"unknown runner backend: {backend}")
