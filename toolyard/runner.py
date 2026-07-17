"""Tool runners.

`ProcessRunner` (dev/CI) exposes secrets from a RAM-backed runtime directory.
`DockerRunner` (production) streams them into a container-only tmpfs at
`/run/secrets` before releasing the image's real command. Secret values never enter a
host file, container layer, environment variable, command argument, or Docker metadata.

Writable secrets travel back through a per-tool Unix socket. Docker subprocess calls
carry timeouts so a wedged daemon cannot hang the admin request that started them.
"""

from __future__ import annotations

import functools
import json
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
_CONTAINER_SECRETS = "/run/secrets"
_INJECTED_MARKER = f"{_CONTAINER_SECRETS}/.toolyard-injected"
_READY_MARKER = f"{_CONTAINER_SECRETS}/.toolyard-ready"
_REPO_ROOT = Path(__file__).resolve().parents[1]  # so `-m toolyard.write_proxy` imports

# Docker subprocess timeouts (seconds): a slow pull or a wedged daemon must fail with a
# clear error, not hang the calling thread (toolyard start/stop runs in an admin request).
_DOCKER_BUILD_TIMEOUT = 600
_DOCKER_RUN_TIMEOUT = 60
_DOCKER_RM_TIMEOUT = 30
_DOCKER_INSPECT_TIMEOUT = 10
# How long start() waits before confirming a process tool didn't immediately exit.
_READINESS_WAIT = 0.3

_BOOTSTRAP_SCRIPT = f"""\
set -eu
while [ ! -e {_READY_MARKER} ]; do sleep 0.05; done
rm -f {_READY_MARKER}
exec \"$@\"
"""

_INJECT_SECRET_SCRIPT = f"""\
set -eu
path={_CONTAINER_SECRETS}/$1
umask 077
cat > \"$path\"
chown \"$2\" \"$path\"
chmod 0400 \"$path\"
"""

_FINALIZE_INJECTION_SCRIPT = f"""\
set -eu
owner=$1
chown \"$owner\" {_CONTAINER_SECRETS}
chmod 0700 {_CONTAINER_SECRETS}
: > {_INJECTED_MARKER}.tmp
chown \"$owner\" {_INJECTED_MARKER}.tmp
chmod 0400 {_INJECTED_MARKER}.tmp
mv {_INJECTED_MARKER}.tmp {_INJECTED_MARKER}
: > {_READY_MARKER}.tmp
chown \"$owner\" {_READY_MARKER}.tmp
chmod 0400 {_READY_MARKER}.tmp
mv {_READY_MARKER}.tmp {_READY_MARKER}
"""

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


@functools.cache
def _boot_id() -> str | None:
    """An id that changes on every reboot, or None where we can't determine one.

    Stamped into each state record so a PID recorded before a reboot is never mistaken for a
    live process of ours; see `_pids_are_ours`.
    """
    try:  # Linux
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip() or None
    except OSError:
        pass
    try:  # macOS/BSD: boot time is as good as an id -- it changes on every boot
        out = subprocess.run(["sysctl", "-n", "kern.boottime"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _pids_are_ours(running: "RunningTool") -> bool:
    """Whether this record's PIDs can still name the processes we spawned.

    The state file outlives the processes in it: after a reboot every PID it holds has been
    recycled by unrelated processes, and we signal *process groups*, so terminating one would
    take out a whole innocent group. (`admin.supervisor._is_broker` guards the broker PID for
    the same reason.) A record stamped with a different -- or unknown -- boot is therefore
    never signalled; those processes are already dead, so there is nothing to reap anyway.
    """
    boot = _boot_id()
    return boot is not None and running.boot_id == boot


def _terminate(pid: str | int | None) -> None:
    """SIGTERM a detached process group (a setpgroup=0 leader) and reap it; best-effort.
    Shared by the write proxy, the egress proxy, the log follower, and start()'s cleanup.

    Callers holding a *persisted* pid must gate this on `_pids_are_ours` first; the pid is
    taken at face value here, which is only safe for one we spawned in this process.
    """
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
    """Best-effort cleanup when start() fails partway: never leave a runtime secrets
    dir, an orphaned write/egress proxy, or an unreaped child zombie behind. start() runs
    inside the long-lived admin handler, so a leaked zombie per failed start would accrue there;
    kill AND reap the tool child and both proxies (a readiness-failed child is already a zombie)."""
    for pid in (child_pid, proxy_pid, log_pid, egress_pid):
        _terminate(pid)
    if proxy_dir:
        shutil.rmtree(proxy_dir, ignore_errors=True)
    if secrets_dir:
        shutil.rmtree(secrets_dir, ignore_errors=True)


@dataclass(frozen=True)
class RunningTool:
    tool_id: str
    port: int
    backend: str
    handle: str  # pid (process) or container name (docker)
    workdir: str  # process runtime dir; empty for Docker (secrets live in container tmpfs)
    proxy_pid: str | None = None  # writable-secret proxy pid (when the tool has one)
    proxy_dir: str | None = None  # proxy socket dir to clean up on stop
    log_pid: str | None = None  # docker log follower pid (process runner logs directly)
    log_path: str | None = None
    egress_pid: str | None = None  # per-tool egress proxy pid (tools with an egress allowlist)
    launcher_pid: str | None = None  # sudo/netguard launcher pid to reap (bwrap backend)
    # Boot this record's pids belong to. Defaults to None so a record written before this
    # field existed reads back as "unknown boot" -> its pids are never signalled.
    boot_id: str | None = None


def _mount_fstype(path: Path) -> str | None:
    """Return the Linux filesystem type containing path, using the kernel mount table."""
    try:
        resolved = path.resolve()
        best: tuple[int, str] | None = None
        for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
            left, sep, right = line.partition(" - ")
            if not sep:
                continue
            fields = left.split()
            mountpoint = Path(fields[4].replace(r"\040", " "))
            if resolved == mountpoint or mountpoint in resolved.parents:
                candidate = (len(str(mountpoint)), right.split()[0])
                if best is None or candidate[0] > best[0]:
                    best = candidate
        return best[1] if best else None
    except OSError:
        return None


def _runtime_root() -> Path:
    """Return a private RAM-backed directory for Toolyard runtime material.

    The systemd unit supplies `/run/toolyard`. Direct CLI/test use falls back to
    `/dev/shm/toolyard`. Fail closed rather than silently writing plaintext to disk.
    """
    configured = os.environ.get("TOOLYARD_RUNTIME_DIR")
    candidates = [Path(configured)] if configured else []
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(Path(xdg_runtime) / "toolyard")
    candidates.extend((Path("/run/toolyard"), Path("/dev/shm/toolyard")))
    errors: list[str] = []
    for root in dict.fromkeys(candidates):
        existing = root
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        if _mount_fstype(existing) not in {"tmpfs", "ramfs"}:
            errors.append(f"{root}: not RAM-backed")
            continue
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            root.chmod(0o700)
            return root
        except OSError as exc:
            errors.append(f"{root}: {exc}")
    raise RuntimeError(
        "no writable RAM-backed Toolyard runtime directory; configure "
        "TOOLYARD_RUNTIME_DIR under tmpfs (" + "; ".join(errors) + ")"
    )


def _runtime_mkdtemp(prefix: str) -> str:
    return tempfile.mkdtemp(prefix=prefix, dir=_runtime_root())


def _write_secrets(tool_id: str, secrets: dict[str, str]) -> str:
    """Materialize process-runner secrets on RAM-backed storage only."""
    from .secrets import protect_secret_memory
    protect_secret_memory()
    secrets_dir = _runtime_mkdtemp(f"toolyard-{tool_id}-")
    try:
        for name, value in secrets.items():
            path = Path(secrets_dir) / name
            path.write_text(value, encoding="utf-8")
            path.chmod(0o600)
    except BaseException:
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
    proxy_dir = _runtime_mkdtemp(f"toolyard-sock-{tool_def.id}-")
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
    # Redirect the proxy's output to the tool log rather than inheriting our stdout/stderr:
    # it outlives this call, so an inherited pipe would never see EOF and any caller that
    # captures our output (redeploy, a boot-time re-up, `toolyard up | tee`) would hang
    # forever on a tool with a writable secret -- long after the start itself succeeded.
    fd = os.open(_tool_log_path(tool_def), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        pid = os.posix_spawn(
            "/bin/sh", ["/bin/sh", "-c", script], os.environ, setpgroup=0,
            file_actions=[(os.POSIX_SPAWN_DUP2, fd, 1),
                          (os.POSIX_SPAWN_DUP2, fd, 2),
                          (os.POSIX_SPAWN_CLOSE, fd)],
        )
    finally:
        os.close(fd)
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
    if _pids_are_ours(running):
        _terminate(running.proxy_pid)
    if running.proxy_dir:
        shutil.rmtree(running.proxy_dir, ignore_errors=True)


def _stop_log_follower(running: RunningTool) -> None:
    if _pids_are_ours(running):
        _terminate(running.log_pid)


def _stop_egress_proxy(running: RunningTool) -> None:
    if _pids_are_ours(running):
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
                                  proxy_pid, proxy_dir, log_path=str(log_path), egress_pid=egress_pid,
                                  boot_id=_boot_id())
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
        # The handle is a pid here, so it is only safe to signal while it still names our
        # process: after a reboot it is some unrelated process's group (see _pids_are_ours).
        if _pids_are_ours(running):
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


_CGROUP_ROOT = "/sys/fs/cgroup"
_NETGUARD_PARENT = "toolyard"          # tool cgroups: /sys/fs/cgroup/toolyard/<id> (see netguard)
_SANDBOX_READINESS_WAIT = 1.0          # sudo + netguard + (bwrap) start is slower than a bare spawn


_SUDO = shutil.which("sudo") or "/usr/bin/sudo"   # absolute: start() launches it via posix_spawn


def _netguard_argv(*args: str) -> list[str]:
    """The privileged netguard invocation. Run under ``sudo -n`` (non-interactive) using the
    broker's own interpreter so ``-m toolyard.netguard`` resolves in the same environment. A
    locked-down NOPASSWD sudoers rule for exactly this command is what keeps the broker itself
    unprivileged (see ``toolyard/netguard.py``). ``sudo`` is resolved to an absolute path because
    ``start()`` launches it with ``posix_spawn`` (which, unlike subprocess, does not search PATH)."""
    return [_SUDO, "-n", sys.executable, "-m", "toolyard.netguard", *args]


def _bwrap_runtime_mount(path: str) -> list[str]:
    """Expose one private runtime directory after bwrap replaces `/dev`.

    Direct CLI runs use `/dev/shm/toolyard`; bwrap's fresh `/dev` hides that path.
    Recreate only the target's parents and bind the per-tool directory read-only.
    """
    target = Path(path)
    args: list[str] = []
    if target == Path("/dev") or Path("/dev") in target.parents:
        parents: list[Path] = []
        parent = target.parent
        while parent != Path("/dev") and parent != parent.parent:
            parents.append(parent)
            parent = parent.parent
        for directory in reversed(parents):
            args += ["--dir", str(directory)]
    return [*args, "--ro-bind", str(target), str(target)]


@functools.lru_cache(maxsize=1)
def _bwrap_usable() -> bool:
    """Whether bwrap can create its (unprivileged) user namespace in the real launch context.
    Some hosts block it -- e.g. Ubuntu 24.04 with ``apparmor_restrict_unprivileged_userns=1`` --
    and there the native runner still confines egress via cgroup+nft but skips bwrap's filesystem
    isolation (the same scope the macOS Seatbelt runner has today). Probed once through the actual
    sudo->netguard path so the answer matches how tools are launched, and cached for the process."""
    if shutil.which("bwrap") is None:
        return False
    probe = "bwrapprobe"
    ok = False
    try:
        r = subprocess.run(_netguard_argv("run", "--tool", probe, "--",
                                          "bwrap", "--dev-bind", "/", "/", "/bin/true"),
                           capture_output=True, text=True, timeout=15)
        ok = r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    finally:
        subprocess.run(_netguard_argv("teardown", "--tool", probe), capture_output=True, timeout=15)
    if not ok:
        log.warning("bwrap unavailable in the sandbox launch context (unprivileged user "
                    "namespaces are likely restricted); the Linux native runner will confine "
                    "egress only, with no filesystem isolation (matching the Seatbelt runner)")
    return ok


class BwrapRunner:
    """Linux-native tool sandbox. Confines a tool's outbound network with a per-tool cgroup v2 +
    nftables rule through the privileged ``netguard`` helper -- deny-all egress by default, new
    outbound only to the tool's loopback egress proxy when it has an allowlist -- and, when the
    host permits an unprivileged user namespace, additionally wraps the launch in bubblewrap for
    filesystem/pid/ipc isolation. The tool runs as the broker's own (non-root) user. Lifecycle is
    keyed to the cgroup (``cgroup.kill`` / reading ``cgroup.procs``), not a pid, since the launch
    goes through ``sudo`` and the broker can neither signal nor reap the resulting root process.

    This is the Linux counterpart of :class:`SeatbeltRunner`; both confine the network today, with
    filesystem/syscall tightening (Landlock + seccomp here) as the next step."""

    backend = "bwrap"

    def _policy(self, tool_def: ToolDef) -> SandboxPolicy:
        return SandboxPolicy(egress=EgressPolicy(allow=tuple(tool_def.egress)))

    def _cgroup_procs(self, tool_id: str) -> str:
        return f"{_CGROUP_ROOT}/{_NETGUARD_PARENT}/{tool_id}/cgroup.procs"

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = None, secrets_file: str | None = None) -> RunningTool:
        if not tool_def.command:
            raise ValueError(f"tool {tool_def.id} has no entrypoint.command")
        _check_port_free(tool_def.port)
        secrets_dir = _write_secrets(tool_def.id, secrets)
        proxy_pid = proxy_dir = None
        egress_pid = egress_port = None
        launcher_pid = None
        log_path = _tool_log_path(tool_def)
        try:
            proxy_pid, proxy_dir = _start_write_proxy(tool_def, secret_backend, secrets_file)
            policy = self._policy(tool_def)
            if policy.egress.allow:
                egress_pid, egress_port = _start_egress_proxy(policy.egress.allow)
            # sudo scrubs the environment, so the tool's env is set inside the inner shell
            # instead of inherited -- the values (paths/port/proxy URL, never secret values)
            # reach the tool regardless of sudo, and the sudoers rule needs no SETENV.
            env_assign = {
                "TOOLSTACK_SECRETS_DIR": secrets_dir,
                "TOOLSTACK_PORT": str(tool_def.port),
                "TOOLSTACK_TOOL_CONFIG": str(tool_def.path / "toolyard.toml"),
            }
            if proxy_dir:
                env_assign["TOOLYARD_SECRETS_SOCKET"] = str(Path(proxy_dir) / "secrets.sock")
            if egress_port:
                proxy_url = f"http://127.0.0.1:{egress_port}"
                for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                    env_assign[var] = proxy_url
            assigns = " ".join(f"{k}={shlex.quote(v)}" for k, v in env_assign.items())
            inner = (f"cd {shlex.quote(str(tool_def.path))} && "
                     f"{assigns} exec {_bind_interpreter(tool_def.command)}")
            launch = ["/bin/sh", "-c", inner]
            if _bwrap_usable():
                # Share the host net ns (the cgroup+nft rule enforces egress); isolate fs/pid/ipc.
                runtime_mounts = _bwrap_runtime_mount(secrets_dir)
                if proxy_dir:
                    runtime_mounts += _bwrap_runtime_mount(proxy_dir)
                launch = ["bwrap", "--dev-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
                          *runtime_mounts,
                          "--unshare-pid", "--unshare-ipc", "--die-with-parent", *launch]
            ng = _netguard_argv("run", "--tool", tool_def.id)
            if egress_port:
                ng += ["--proxy-port", str(egress_port)]
            argv = [*ng, "--", *launch]
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                launcher_pid = os.posix_spawn(
                    argv[0], argv, os.environ, setpgroup=0,
                    file_actions=[(os.POSIX_SPAWN_DUP2, log_fd, 1),
                                  (os.POSIX_SPAWN_DUP2, log_fd, 2),
                                  (os.POSIX_SPAWN_CLOSE, log_fd)],
                )
            finally:
                os.close(log_fd)
            running = RunningTool(tool_def.id, tool_def.port, self.backend, tool_def.id,
                                  secrets_dir, proxy_pid, proxy_dir, log_path=str(log_path),
                                  egress_pid=egress_pid, launcher_pid=str(launcher_pid),
                                  boot_id=_boot_id())
            # Readiness: netguard joins the cgroup before exec, so after a short settle a live
            # tool leaves the cgroup non-empty while one that exited at once leaves it empty.
            time.sleep(_SANDBOX_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} did not start under the sandbox: see {log_path}")
            log.info("started tool %s on 127.0.0.1:%s under %s (cgroup %s, log %s)",
                     tool_def.id, tool_def.port, self.backend, tool_def.id, log_path)
            return running
        except BaseException:
            subprocess.run(_netguard_argv("teardown", "--tool", tool_def.id),
                           capture_output=True, timeout=15)  # remove the cgroup + nft rule
            _cleanup_partial_start(secrets_dir, proxy_pid, proxy_dir,
                                   child_pid=launcher_pid, egress_pid=egress_pid)
            raise

    def stop(self, running: RunningTool) -> None:
        # cgroup.kill (via teardown) SIGKILLs the tool even though the broker can't signal it
        # directly; then reap the sudo launcher and clean up the proxies + secrets dir.
        subprocess.run(_netguard_argv("teardown", "--tool", running.handle),
                       capture_output=True, timeout=15)
        if _pids_are_ours(running):
            _terminate(running.launcher_pid)
        _stop_proxy(running)
        _stop_egress_proxy(running)
        shutil.rmtree(running.workdir, ignore_errors=True)
        log.info("stopped tool %s (cgroup %s)", running.tool_id, running.handle)

    def is_alive(self, running: RunningTool) -> bool:
        try:
            with open(self._cgroup_procs(running.handle)) as f:
                return bool(f.read().strip())
        except OSError:
            return False


class DockerRunner:
    backend = "docker"

    _IMAGE_CONFIG_FORMAT = (
        '{"entrypoint":{{json .Config.Entrypoint}},'
        '"cmd":{{json .Config.Cmd}},"user":{{json .Config.User}}}'
    )

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

    @staticmethod
    def _docker_input(args: list[str], payload: bytes, timeout: float) -> None:
        """Send secret bytes to Docker over stdin without putting them in argv or env."""
        try:
            subprocess.run(
                ["docker", *args], input=payload, capture_output=True,
                check=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"docker {args[0]} timed out after {timeout:.0f}s") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"docker {args[0]} failed: {detail or exc}") from exc

    def _image_runtime(self, image: str) -> tuple[list[str], str]:
        result = self._docker(
            ["image", "inspect", "--format", self._IMAGE_CONFIG_FORMAT, image],
            _DOCKER_INSPECT_TIMEOUT, check=True,
        )
        try:
            config = json.loads(result.stdout)
            command = [*(config.get("entrypoint") or []), *(config.get("cmd") or [])]
            owner = config.get("user") or "0:0"
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError(f"could not read runtime command for image {image}") from exc
        if not command:
            raise RuntimeError(f"image {image} has no ENTRYPOINT or CMD")
        return [str(arg) for arg in command], str(owner)

    def _inject_secrets(self, container: str, owner: str, secrets: dict[str, str]) -> None:
        for name, value in secrets.items():
            self._docker_input(
                ["exec", "-i", "--user", "0", container, "/bin/sh", "-c",
                 _INJECT_SECRET_SCRIPT, "toolyard-inject", name, owner],
                value.encode("utf-8"), _DOCKER_RUN_TIMEOUT,
            )
        self._docker(
            ["exec", "--user", "0", container, "/bin/sh", "-c",
             _FINALIZE_INJECTION_SCRIPT, "toolyard-finalize", owner],
            _DOCKER_RUN_TIMEOUT, check=True,
        )

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = None, secrets_file: str | None = None) -> RunningTool:
        from .secrets import protect_secret_memory
        protect_secret_memory()
        proxy_pid = proxy_dir = None
        name = None
        log_pid = None
        log_path = _tool_log_path(tool_def)
        try:
            proxy_pid, proxy_dir = _start_write_proxy(tool_def, secret_backend, secrets_file)
            rest_generic = tool_def.type == "rest" and tool_def.image is None
            image = tool_def.image or ("python:3.13-slim" if rest_generic else f"toolstack-{tool_def.id}")
            if tool_def.image is None and not rest_generic:
                self._docker(["build", "-t", image, str(tool_def.path)], _DOCKER_BUILD_TIMEOUT, check=True)
            image_command, image_user = self._image_runtime(image)
            if rest_generic:
                image_command = ["python3", "-m", "toolstack_forwarder"]
            name = f"toolyard-{tool_def.id}"
            self._docker(["rm", "-f", name], _DOCKER_RM_TIMEOUT)  # clear a same-named leftover
            run_args = [
                "run", "-d", "--name", name,
                "-p", f"127.0.0.1:{tool_def.port}:{tool_def.port}",
                "-e", f"TOOLSTACK_PORT={tool_def.port}",
                "-e", "TOOLSTACK_BIND=0.0.0.0",  # container-internal; host side stays loopback via -p
                "-e", f"TOOLSTACK_SECRETS_DIR={_CONTAINER_SECRETS}",
                "--tmpfs", f"{_CONTAINER_SECRETS}:rw,noexec,nosuid,nodev,mode=0711",
                "--ulimit", "core=0:0",
                "--entrypoint", "/bin/sh",
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
            run_args += [image, "-c", _BOOTSTRAP_SCRIPT, "toolyard-init", *image_command]
            self._docker(run_args, _DOCKER_RUN_TIMEOUT, check=True)
            self._inject_secrets(name, image_user, secrets)
            log_pid = _start_docker_log_follower(name, log_path)
            running = RunningTool(tool_def.id, tool_def.port, self.backend, name, "",
                                  proxy_pid, proxy_dir, log_pid=log_pid, log_path=str(log_path),
                                  boot_id=_boot_id())
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
            _cleanup_partial_start("", proxy_pid, proxy_dir, log_pid=log_pid)
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
        if running.workdir:  # clean records created by the retired host-file implementation
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

    def secrets_ready(self, running: RunningTool) -> bool:
        """Whether this live container still has Toolyard's tmpfs injection marker."""
        try:
            result = subprocess.run(
                ["docker", "exec", running.handle, "test", "-e", _INJECTED_MARKER],
                capture_output=True, timeout=_DOCKER_INSPECT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return False
        return result.returncode == 0


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
        return BwrapRunner()
    raise ValueError(f"unknown runner backend: {backend}")
