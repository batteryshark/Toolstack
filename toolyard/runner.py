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

import functools
import logging
import os
import re
import secrets as _secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import ToolDef
from .sandbox import EgressPolicy, ResourceCaps, SandboxPolicy

# SPS integration (Phase 2): the runner mints an ephemeral E_SECRET per
# tool start, registers the tool with SPS over TLS/TCP, and injects the
# E_SECRET + SPS connection params into the child env. The tool itself
# then talks to SPS to retrieve its secrets (see Phase 3 tool migration).
_DEFAULT_SPS_ENV = "/etc/toolstack/sps.env"
_DEFAULT_SPS_CA = "/etc/toolstack/sps-ca.crt"
_DEFAULT_SPS_HOST = "127.0.0.1"
_DEFAULT_SPS_PORT = 8743

# Container-internal mount point for the toml (the forwarder reads it).
_CONTAINER_TOOL_CONFIG = "/run/toolstack/toolyard.toml"
_REPO_ROOT = Path(__file__).resolve().parents[1]  # so the runner can posix_spawn a sub-shell

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


# ---- SPS integration (Phase 2) --------------------------------------------

def _mint_e_secret() -> str:
    """64 random bytes -> 128 hex chars. Per tool start."""
    return _secrets.token_hex(64)


def _check_sps_env(path: str) -> str:
    """Fail closed: sps.env must be present and mode 0600 (the SPS config
    module raises ConfigModeError if not). Called by `runner.start()` BEFORE
    `_sps_register` so a misconfigured SPS is caught at the gate rather than
    at the wire."""
    from sps.config import ConfigModeError, load_config
    try:
        load_config(path)
    except ConfigModeError as exc:
        raise SystemExit(f"sps.env: {exc}") from exc
    except FileNotFoundError as exc:
        raise SystemExit(f"sps.env not found at {path}: {exc}") from exc
    except ValueError as exc:
        raise SystemExit(f"sps.env: {exc}") from exc
    return path


def _sps_register(tool_def: ToolDef, e_secret: str, sps_env_path: str) -> None:
    """Open a TLS connection to SPS, verify the cert against `sp_tls_ca`,
    send a `register` JSON line carrying the tool's CS_TUPLE list."""
    from sps.client import SPSClient
    from sps.config import load_config
    cfg = load_config(sps_env_path)
    verify = os.environ.get("TOOLSTACK_SPS_VERIFY", "1") == "1"
    client = SPSClient(
        host=os.environ.get("TOOLSTACK_SPS_HOST", cfg.sp_host),
        port=int(os.environ.get("TOOLSTACK_SPS_PORT", str(cfg.sp_port))),
        sp_secret=cfg.sp_secret,
        ca_file=cfg.sp_tls_ca,
        verify=verify,
    )
    cs_tuples = [
        {"name": s.name, "field": s.field, "item": s.item, "writable": bool(s.writable)}
        for s in tool_def.secrets
    ]
    client.register(tool_def.id, e_secret, cs_tuples)


def _sps_unregister(tool_id: str, sps_env_path: str) -> None:
    """Best-effort: a failed unregister should not turn a clean stop into a
    failure. Logged as a warning, never raised to the caller."""
    from sps.client import SPSClient
    from sps.config import load_config
    try:
        cfg = load_config(sps_env_path)
    except Exception as exc:
        log.warning("SPS unregister %s: cannot load config %s: %s", tool_id, sps_env_path, exc)
        return
    try:
        verify = os.environ.get("TOOLSTACK_SPS_VERIFY", "1") == "1"
        client = SPSClient(
            host=os.environ.get("TOOLSTACK_SPS_HOST", cfg.sp_host),
            port=int(os.environ.get("TOOLSTACK_SPS_PORT", str(cfg.sp_port))),
            sp_secret=cfg.sp_secret,
            ca_file=cfg.sp_tls_ca,
            verify=verify,
        )
        client.unregister(tool_id)
    except Exception as exc:
        log.warning("SPS unregister %s failed: %s", tool_id, exc)


def _terminate(pid: str | int | None) -> None:
    """SIGTERM a detached process group (a setpgroup=0 leader) and reap it; best-effort.
    Shared by the write proxy, the egress proxy, the log follower, and start()'s cleanup."""
    if pid is None:
        return
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return  # docker container names and other non-numeric handles are not killpg targets
    # Safety: never signal pid ≤ 1. POSIX interprets -1 as "every process we own" and 1 as
    # init; the runner only ever calls this with its own posix_spawn children's pids (always
    # ≥ 2 in practice), so a value ≤ 1 means a sentinel leaked through. Refuse rather than
    # signal wrongly. (Matches the repo-wide "kill pid 1 is a footgun" invariant.)
    if pid_int <= 1:
        log.warning("_terminate: refusing unsafe pid %r (≤1 would signal init or every process)", pid)
        return
    try:
        os.killpg(pid_int, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        os.waitpid(pid_int, 0)
    except (ChildProcessError, ProcessLookupError):
        pass


def _cleanup_partial_start(child_pid: int | None = None,
                           log_pid: str | None = None,
                           egress_pid: str | None = None) -> None:
    """Best-effort cleanup when start() fails partway. Phase 5: no secrets
    dir mount, no write-proxy socket dir -- just reap any zombie children
    the tool wouldn't have inherited (e.g. bwrap sudo launcher, the
    docker log follower). start() runs inside the long-lived admin handler;
    a leaked zombie per failed start would accrue there."""
    for pid in (child_pid, log_pid, egress_pid):
        _terminate(pid)


@dataclass(frozen=True)
class RunningTool:
    tool_id: str
    port: int
    backend: str
    handle: str  # pid (process) or container name (docker)
    log_pid: str | None = None  # docker log follower pid (process runner logs directly)
    log_path: str | None = None
    egress_pid: str | None = None  # per-tool egress proxy pid (tools with an egress allowlist)
    launcher_pid: str | None = None  # sudo/netguard launcher pid to reap (bwrap backend)
    # SPS integration (Phase 2): the E_SECRET the runner minted for this start,
    # plus the SPS connection params the tool needs to retrieve its secrets.
    e_secret: str | None = None
    sps_host: str = "127.0.0.1"
    sps_port: int = 8743
    sps_ca: str | None = None


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

    def start(self, tool_def: ToolDef) -> RunningTool: ...

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

    def start(self, tool_def: ToolDef) -> RunningTool:
        """Spawn the tool as a subprocess. Phase 5: the runner no longer
        resolves secrets from a backend -- the tool pulls them from SPS at
        boot, using the E_SECRET we mint here and a CA bundle the runner
        sets in the env."""
        if not tool_def.command:
            raise ValueError(f"tool {tool_def.id} has no entrypoint.command")
        _check_port_free(tool_def.port)

        # SPS integration: when configured (env file present, mode 0600),
        # mint an ephemeral E_SECRET and register the tool with SPS so the
        # tool can retrieve its secrets over TLS/TCP. When unconfigured (dev
        # path), run the tool in "no-secrets" mode and let the tool report
        # has_api_key: False. Tests can disable the SPS path entirely via
        # TOOLSTACK_SPS_SKIP=1.
        sps_env_path = os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_SPS_ENV)
        sps_active = (
            os.environ.get("TOOLSTACK_SPS_SKIP") != "1"
            and os.path.exists(sps_env_path)
        )
        e_secret = _mint_e_secret() if sps_active else None
        sps_registered = False
        if sps_active:
            try:
                _check_sps_env(sps_env_path)
                _sps_register(tool_def, e_secret, sps_env_path)  # type: ignore[arg-type]
                sps_registered = True
            except SystemExit:
                # Mode-0600 failure already logged by _check_sps_env; do not
                # silently keep going -- refuse to launch.
                raise
            except Exception as exc:
                log.warning("SPS register %s failed: %s (skipping SPS path)", tool_def.id, exc)
                e_secret = None
                sps_registered = False

        egress_pid = egress_port = None
        child_pid = None
        log_path = _tool_log_path(tool_def)
        try:
            policy = self._policy(tool_def)
            if policy.egress.allow:
                egress_pid, egress_port = _start_egress_proxy(policy.egress.allow)
            env = {
                **os.environ,
                "TOOLSTACK_PORT": str(tool_def.port),
                "TOOLSTACK_TOOL_CONFIG": str(tool_def.path / "toolyard.toml"),
            }
            if e_secret is not None:
                env["TOOLSTACK_E_SECRET"] = e_secret
                env["TOOLSTACK_SPS_HOST"] = os.environ.get(
                    "TOOLSTACK_SPS_HOST", _DEFAULT_SPS_HOST)
                env["TOOLSTACK_SPS_PORT"] = os.environ.get(
                    "TOOLSTACK_SPS_PORT", str(_DEFAULT_SPS_PORT))
                env["TOOLSTACK_SPS_CA"] = os.environ.get(
                    "TOOLSTACK_SPS_CA", _DEFAULT_SPS_CA)
            if egress_port:
                # Route the tool's outbound HTTP(S) through its egress proxy; the sandbox
                # allows outbound only to this port, so the proxy is the sole exit.
                proxy_url = f"http://127.0.0.1:{egress_port}"
                for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                    env[var] = proxy_url
            # posix_spawn (not Popen) so the detached child has no lifecycle object to
            # warn about; setpgroup=0 gives it its own group so stop() can killpg it.
            inner_script = f"cd {shlex.quote(str(tool_def.path))} && exec {_bind_interpreter(tool_def.command)}"
            executable, argv = self._spawn_argv(tool_def, inner_script, None, egress_port)
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
            child_pid = pid
            running = RunningTool(
                tool_def.id, tool_def.port, self.backend, str(pid),
                log_path=str(log_path), egress_pid=egress_pid,
                e_secret=e_secret,
                sps_host=env.get("TOOLSTACK_SPS_HOST", _DEFAULT_SPS_HOST),
                sps_port=int(env.get("TOOLSTACK_SPS_PORT", str(_DEFAULT_SPS_PORT))),
                sps_ca=env.get("TOOLSTACK_SPS_CA") if e_secret else None,
            )
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} exited immediately on start: see {log_path}")
            log.info("started tool %s on 127.0.0.1:%s (pid %s, log %s, sps=%s)",
                     tool_def.id, tool_def.port, pid, log_path, sps_registered)
            return running
        except BaseException:
            _cleanup_partial_start(child_pid, egress_pid=egress_pid)
            if sps_registered:
                try:
                    _sps_unregister(tool_def.id, sps_env_path)
                except Exception:
                    pass
            raise

    def stop(self, running: RunningTool) -> None:
        pid = int(running.handle)
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            os.waitpid(pid, 0)
        except (ChildProcessError, ProcessLookupError):
            pass
        _stop_log_follower(running)
        _stop_egress_proxy(running)
        if running.e_secret:
            try:
                _sps_unregister(
                    running.tool_id,
                    os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_SPS_ENV),
                )
            except Exception as exc:
                log.warning("SPS unregister %s on stop: %s", running.tool_id, exc)
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

    def start(self, tool_def: ToolDef) -> RunningTool:
        if not tool_def.command:
            raise ValueError(f"tool {tool_def.id} has no entrypoint.command")
        _check_port_free(tool_def.port)
        egress_pid = egress_port = None
        launcher_pid = None
        log_path = _tool_log_path(tool_def)
        try:
            policy = self._policy(tool_def)
            if policy.egress.allow:
                egress_pid, egress_port = _start_egress_proxy(policy.egress.allow)
            # sudo scrubs the environment, so the tool's env is set inside the inner shell
            # instead of inherited -- the values (paths/port/proxy URL, never secret values)
            # reach the tool regardless of sudo, and the sudoers rule needs no SETENV.
            env_assign = {
                "TOOLSTACK_PORT": str(tool_def.port),
                "TOOLSTACK_TOOL_CONFIG": str(tool_def.path / "toolyard.toml"),
            }
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
                launch = ["bwrap", "--dev-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
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
                                  log_path=str(log_path),
                                  egress_pid=egress_pid, launcher_pid=str(launcher_pid))
            time.sleep(_SANDBOX_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} did not start under the sandbox: see {log_path}")
            log.info("started tool %s on 127.0.0.1:%s under %s (cgroup %s, log %s)",
                     tool_def.id, tool_def.port, self.backend, tool_def.id, log_path)
            return running
        except BaseException:
            subprocess.run(_netguard_argv("teardown", "--tool", tool_def.id),
                           capture_output=True, timeout=15)  # remove the cgroup + nft rule
            _cleanup_partial_start(child_pid=launcher_pid, egress_pid=egress_pid)
            raise

    def stop(self, running: RunningTool) -> None:
        # cgroup.kill (via teardown) SIGKILLs the tool even though the broker can't signal it
        # directly; then reap the sudo launcher.
        subprocess.run(_netguard_argv("teardown", "--tool", running.handle),
                       capture_output=True, timeout=15)
        _terminate(running.launcher_pid)
        _stop_egress_proxy(running)
        log.info("stopped tool %s (cgroup %s)", running.tool_id, running.handle)

    def is_alive(self, running: RunningTool) -> bool:
        try:
            with open(self._cgroup_procs(running.handle)) as f:
                return bool(f.read().strip())
        except OSError:
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

    def start(self, tool_def: ToolDef) -> RunningTool:
        # Phase 5: no secrets-dir bind mount, no write-proxy. Tools pull
        # from SPS via the env vars the runner injects. The container
        # only needs the toolyard.toml (for the forwarder) and the
        # egress proxy mount when an egress allowlist is in effect.
        name = None
        log_pid = None
        log_path = _tool_log_path(tool_def)
        try:
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
            ]
            # Carry the SPS connection env through so the SDK can find the server.
            for var in ("TOOLSTACK_E_SECRET", "TOOLSTACK_SPS_HOST",
                         "TOOLSTACK_SPS_PORT", "TOOLSTACK_SPS_CA"):
                if var in os.environ:
                    run_args += ["-e", f"{var}={os.environ[var]}"]
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
            run_args.append(image)
            if rest_generic:
                run_args += ["python3", "-m", "toolstack_forwarder"]
            self._docker(run_args, _DOCKER_RUN_TIMEOUT, check=True)
            log_pid = _start_docker_log_follower(name, log_path)
            running = RunningTool(tool_def.id, tool_def.port, self.backend, name,
                                  log_pid=log_pid, log_path=str(log_path))
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} container exited immediately: see {log_path}")
            log.info("started tool %s in container %s on :%s (log %s)",
                     tool_def.id, name, tool_def.port, log_path)
            return running
        except BaseException:
            if name:
                try:
                    subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                                   timeout=_DOCKER_RM_TIMEOUT)
                except subprocess.TimeoutExpired:
                    pass
            _cleanup_partial_start(log_pid=log_pid)
            raise

    def stop(self, running: RunningTool) -> None:
        _stop_log_follower(running)
        try:
            r = subprocess.run(["docker", "rm", "-f", running.handle],
                               capture_output=True, text=True, timeout=_DOCKER_RM_TIMEOUT)
            if r.returncode != 0:
                log.warning("docker rm %s failed on stop (rc=%s): %s; container may still exist",
                            running.handle, r.returncode, (r.stderr or "").strip())
        except subprocess.TimeoutExpired:
            log.warning("docker rm %s timed out on stop; container may still exist", running.handle)
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
        return BwrapRunner()
    raise ValueError(f"unknown runner backend: {backend}")
