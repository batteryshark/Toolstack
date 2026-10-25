"""Tool runners. Process mode is for trusted same-owner tools only.
File modes and separate channel credentials are not OS isolation: another
unrestricted process owned by the same account can read private runner state.

Process tools receive an SPS capability and an independent API channel capability.
The broker channel view contains only the latter. Response visibility still depends
on each tool: writeback is not automatic redaction. Docker/Seatbelt SPS lifecycle
is not yet validated, and the mutable privileged Linux helper launch is disabled.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import secrets as _secrets
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
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


def _child_environment() -> dict[str, str]:
    """Only runtime plumbing crosses into tools/helpers; SPS/provider masters don't.

    Custom workload credentials belong in SPS, not inherited runner environment.
    This reduces accidental disclosure, not same-account filesystem authority.
    """
    allowed = {"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "TZ",
               "PYTHONPATH", "VIRTUAL_ENV", "PYTHONUNBUFFERED", "SSL_CERT_FILE",
               "SSL_CERT_DIR", "TOOLSTACK_SPS_FAKE"}
    return {key: value for key, value in os.environ.items()
            if key in allowed or key.startswith("LC_")}


def _tool_log_path(tool_def: ToolDef) -> Path:
    """Per-tool logfile in the tool folder (`logs/tool.log`) so tool output travels with
    the tool, not an opaque global state directory."""
    d = tool_def.path / "logs"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
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
    """Return an identifier that changes on reboot, when the OS exposes one."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip() or None
    except OSError:
        pass
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() or None if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _process_identity(pid: str | int | None) -> str | None:
    if pid is None:
        return None
    try:
        if sys.platform.startswith("linux"):
            text = Path(f"/proc/{int(pid)}/stat").read_text()
            return text[text.rfind(")") + 2:].split()[19]
        if sys.platform == "darwin":
            # Darwin proc_bsdinfo ends with uint64 start_tvsec/start_tvusec.
            # Unlike ps lstart, this retains microseconds for same-boot reuse.
            import ctypes
            import struct
            library = ctypes.CDLL("/usr/lib/libproc.dylib")
            info = ctypes.create_string_buffer(136)
            size = library.proc_pidinfo(int(pid), 3, 0, info, len(info))
            if size == len(info):
                seconds, micros = struct.unpack_from("=QQ", info.raw, 120)
                return f"{seconds}:{micros}"
        return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _pids_are_current(running: "RunningTool") -> bool:
    """Whether persisted PIDs in this record belong to the current boot."""
    current = _boot_id()
    return (current is not None and running.boot_id == current and
            running.process_identity is not None and
            _process_identity(running.handle) == running.process_identity)


# ---- SPS re-registration helper (used by the admin watchdog) ---------------
# SPS state is in-memory only (see sps/store.py). When SPS restarts -- crash,
# library upgrade, manual -- every running tool's registration is lost, and
# subsequent SPS calls (writeback, get_secrets, refresh) fail with "Not found".
# The runner re-registers on every fresh tool start; this helper re-registers
# already-running tools without bouncing them, called by the admin watchdog
# when it sees a new SPS boot_id.
def reregister_all_with_sps(**kwargs) -> int:
    """Compatibility count wrapper; watchdogs should use the detailed helper."""
    return sum(error is None for error in reregister_with_sps_results(**kwargs).values())


@dataclass(frozen=True)
class SPSRecoveryResult:
    succeeded: tuple[str, ...]
    failed: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.failed

    @property
    def count(self) -> int:
        return len(self.succeeded)


def reregister_all_with_sps_detailed(**kwargs) -> SPSRecoveryResult:
    results = reregister_with_sps_results(**kwargs)
    return SPSRecoveryResult(tuple(k for k, v in results.items() if v is None),
                             tuple(k for k, v in results.items() if v is not None))


def reregister_with_sps_results(*, tools_root: str, tool_dirs, sps_env_path: str) -> dict[str, str | None]:
    from .cli import state_lock
    with state_lock():
        return _reregister_results(tools_root=tools_root, tool_dirs=tool_dirs,
                                   sps_env_path=sps_env_path)


def _reregister_results(*, tools_root: str, tool_dirs, sps_env_path: str) -> dict[str, str | None]:
    """Re-register every tool currently in the toolyard state file with SPS.

    Idempotent: calling it for tools that are already registered is a no-op
    (SPS.register overwrites). Returns the number of tools successfully
    re-registered. Skips tools with no e_secret in their state record
    (they were started without SPS, so there's nothing to re-register).

    Used by ``admin.sps_watchdog`` whenever SPS announces a new boot_id.
    """
    if not os.path.exists(sps_env_path):
        log.warning("SPS re-register: sps.env not found at %s; skipping", sps_env_path)
        raise RunnerConfigError("SPS configuration missing; recovery must retry")
    from .cli import _load_state
    from .config import discover, load as load_tool
    state = _load_state()
    if not state:
        return {}
    defs: dict[str, ToolDef] = {}
    if tools_root:
        for d in discover(tools_root):
            defs[d.id] = d
    for path in tool_dirs or ():
        toml_path = Path(path) / "toolyard.toml"
        if toml_path.exists():
            try:
                defs[load_tool(toml_path).id] = load_tool(toml_path)
            except Exception as exc:
                log.warning("SPS re-register: cannot load %s: %s", toml_path, exc)
    results = {}
    for tool_id, rec in state.items():
        if not isinstance(rec, dict):
            continue
        e_secret = rec.get("e_secret")
        if not e_secret:
            continue
        try:
            running = RunningTool(**rec)
            alive = get_runner(running.backend).is_alive(running)
        except Exception as exc:
            # Can't prove the tool is dead; register anyway (idempotent) rather
            # than risk orphaning a live tool.
            log.warning("SPS re-register: cannot liveness-check %s (%s); registering anyway",
                        tool_id, exc)
            alive = True
        if not alive:
            continue  # positively dead; reconcile restarts it
        tool_def = defs.get(tool_id)
        if tool_def is None:
            log.warning("SPS re-register: tool %s has e_secret but no tool_def", tool_id)
            results[tool_id] = "tool definition missing"
            continue
        try:
            _sps_register(tool_def, e_secret, sps_env_path)
            results[tool_id] = None
            log.info("SPS re-registered %s", tool_id)
        except Exception as exc:
            log.warning("SPS re-register %s failed: %s", tool_id, exc)
            results[tool_id] = "registration failed"
    return results


# ---- SPS integration (Phase 2) --------------------------------------------

def _mint_e_secret() -> str:
    """64 random bytes -> 128 hex chars. Per tool start."""
    return _secrets.token_hex(64)


class RunnerConfigError(ValueError):
    """Invalid runner/SPS configuration (safe for ordinary exception handlers)."""


def strict_bool(value: str) -> bool:
    from sps.config import parse_bool
    try:
        return parse_bool(value, name="TOOLSTACK_SPS_VERIFY")
    except ValueError as exc:
        raise RunnerConfigError(str(exc)) from exc


@dataclass(frozen=True)
class ResolvedSPS:
    sp_host: str
    sp_port: int
    sp_secret: str = field(repr=False)
    sp_tls_ca: str
    verify: bool


def _resolve_sps(path):
    from sps.config import load_config
    try:
        cfg = load_config(path)
        return ResolvedSPS(os.environ.get("TOOLSTACK_SPS_HOST", cfg.sp_host),
                           int(os.environ.get("TOOLSTACK_SPS_PORT", cfg.sp_port)),
                           cfg.sp_secret, os.environ.get("TOOLSTACK_SPS_CA", cfg.sp_tls_ca),
                           strict_bool(os.environ.get("TOOLSTACK_SPS_VERIFY", "1")))
    except (OSError, ValueError, RuntimeError) as exc:
        raise RunnerConfigError(f"invalid SPS configuration: {exc}") from exc


def _check_sps_env(path: str) -> str:
    """Compatibility validation entry point; start resolves/validates once instead."""
    from sps.config import ConfigModeError, load_config
    try:
        load_config(path)
    except ConfigModeError as exc:
        raise RunnerConfigError(f"sps.env: {exc}") from exc
    except FileNotFoundError as exc:
        raise RunnerConfigError(f"sps.env not found at {path}: {exc}") from exc
    except ValueError as exc:
        raise RunnerConfigError(f"sps.env: {exc}") from exc
    return path


def _sps_register(tool_def: ToolDef, e_secret: str, sps_env_path: str) -> None:
    """Open a TLS connection to SPS, verify the cert against `sp_tls_ca`,
    send a `register` JSON line carrying the tool's CS_TUPLE list."""
    from sps.client import SPSClient
    cfg = _resolve_sps(sps_env_path) if isinstance(sps_env_path, str) else sps_env_path
    client = SPSClient(
        host=cfg.sp_host,
        port=cfg.sp_port,
        sp_secret=cfg.sp_secret,
        ca_file=cfg.sp_tls_ca,
        verify=cfg.verify,
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
        cfg = _resolve_sps(sps_env_path)
    except Exception as exc:
        log.warning("SPS unregister %s: cannot load config %s: %s", tool_id, sps_env_path, exc)
        return
    try:
        client = SPSClient(
            host=cfg.sp_host,
            port=cfg.sp_port,
            sp_secret=cfg.sp_secret,
            ca_file=cfg.sp_tls_ca,
            verify=cfg.verify,
        )
        client.unregister(tool_id)
    except Exception as exc:
        log.warning("SPS unregister %s failed: %s", tool_id, exc)


def _pid_absent(pid: int) -> bool:
    """Only ESRCH is positive absence; snapshot failure and EPERM are not.

    Signal zero is a non-delivering probe of this single PID, never its group.
    It cannot establish the fate of arbitrary descendants of a departed leader.
    """
    if pid <= 1:
        raise RuntimeError("invalid process handle; retain state")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError as exc:
        raise RuntimeError("process absence unconfirmed; retain state") from exc
    return False


def _terminate(pid: str | int | None, identity: str | None = None,
               boot_id: str | None = None) -> None:
    """Reap before signalling; require a positive boot/start match for each signal.

    Missing identity, permission failure and an unavailable process snapshot are
    uncertainty, not evidence of exit. Reaping, positive OS absence, or a known
    different boot confirm that the recorded runtime no longer exists.
    This is trusted same-owner bookkeeping, not hostile-owner isolation.
    """
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
    def reaped():
        try:
            return os.waitpid(pid_int, os.WNOHANG)[0] == pid_int
        except ChildProcessError:
            return False

    # Never reap a potentially reused PID when a known identity differs. An
    # unknown snapshot can still be resolved by a positive own-child waitpid.
    def check_exit():
        current_boot = _boot_id()
        if boot_id and current_boot and boot_id != current_boot:
            return True  # No PID probes, reaps or signals across a known reboot.
        if boot_id and current_boot is None:
            raise RuntimeError("process boot identity unconfirmed; retain state")
        current = _process_identity(pid_int)
        if identity is not None and current is not None and current != identity:
            # Original leader is gone, but its group may survive. Do not reap or
            # signal the replacement and do not invent a whole-cleanup receipt.
            raise RuntimeError("process identity changed; retain state")
        if reaped():
            return True
        if not boot_id or not current_boot:
            raise RuntimeError("process boot identity unconfirmed; retain state")
        return _pid_absent(pid_int)

    if check_exit():
        return
    for sig, delay in ((signal.SIGTERM, 2), (signal.SIGKILL, 1)):
        if (not boot_id or _boot_id() != boot_id or not identity or
                _process_identity(pid_int) != identity):
            raise RuntimeError("process identity unconfirmed; retain state")
        try:
            os.killpg(pid_int, sig)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            # Darwin zombies can report EPERM: reaping/ESRCH can still resolve it.
            if check_exit():
                return
            raise RuntimeError("process signal denied; retain state") from exc
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline:
            if check_exit():
                return
            time.sleep(0.05)
        if check_exit():
            return
    raise RuntimeError("process stop unconfirmed; retain state")


def _cleanup_partial_start(running: "RunningTool") -> "RunningTool":
    """Attempt every known child, preserving identities and positive exit receipts."""
    failed = False
    children = [("log", running.log_pid), ("egress", running.egress_pid)]
    if running.backend in ("process", "seatbelt"):
        children.insert(0, ("process", running.handle or None))
    for kind, pid in children:
        if pid is None or getattr(running, f"{kind}_exited"):
            continue
        try:
            if int(pid) <= 1:
                raise ValueError("invalid process handle")
            _terminate(pid, getattr(running, f"{kind}_identity"), running.boot_id)
            running = replace(running, **{f"{kind}_exited": True})
        except BaseException:
            failed = True
    if failed:
        raise RunnerStartCleanupError(running)
    return running


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
    # A persisted PID may be recycled after reboot. Old records (without this field)
    # deserialize as unknown and are never probed or signalled by PID.
    boot_id: str | None = None
    channel_secret: str | None = None
    process_identity: str | None = None
    log_identity: str | None = None
    egress_identity: str | None = None
    # Positive exit receipts (reap, ESRCH, known prior boot) survive retries.
    process_exited: bool = False
    log_exited: bool = False
    egress_exited: bool = False


class RunnerStartCleanupError(RuntimeError):
    """Start failed but cleanup is unconfirmed: persist running for later recovery."""

    def __init__(self, running: RunningTool):
        super().__init__(f"start cleanup failed for {running.tool_id}; retain state record")
        self.running = running


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
    pid = os.posix_spawn("/bin/sh", ["/bin/sh", "-c", script], _child_environment(), setpgroup=0)
    return str(pid), port


def _stop_log_follower(running: RunningTool) -> None:
    if running.log_pid and not running.log_exited:
        _terminate(running.log_pid, running.log_identity, running.boot_id)


def _stop_egress_proxy(running: RunningTool) -> None:
    if running.egress_pid and not running.egress_exited:
        _terminate(running.egress_pid, running.egress_identity, running.boot_id)


def _start_docker_log_follower(container: str, log_path: Path, *, _on_spawn=None) -> str:
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    try:
        pid = os.posix_spawn(
            "/usr/bin/env",
            ["env", "docker", "logs", "-f", container],
            _child_environment(),
            setpgroup=0,
            file_actions=[(os.POSIX_SPAWN_DUP2, fd, 1),
                          (os.POSIX_SPAWN_DUP2, fd, 2),
                          (os.POSIX_SPAWN_CLOSE, fd)],
        )
        if _on_spawn is not None:
            _on_spawn(str(pid))
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

        # Required secrets fail closed. Only explicit trusted-process development
        # may opt out with TOOLSTACK_SPS_SKIP=1.
        sps_env_path = os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_SPS_ENV)
        sps_active = (
            os.environ.get("TOOLSTACK_SPS_SKIP") != "1"
            and os.path.exists(sps_env_path)
        )
        if (sps_active or tool_def.secrets) and self.backend != "process":
            raise RunnerConfigError(f"{self.backend} + SPS lifecycle is not validated")
        if tool_def.secrets and not sps_active:
            if os.environ.get("TOOLSTACK_SPS_SKIP") != "1":
                raise RunnerConfigError("tool declares secrets but SPS configuration is absent")
            log.warning("DEVELOPMENT ONLY: TOOLSTACK_SPS_SKIP=1; tool %s launches without declared secrets",
                        tool_def.id)
        channel_secret = _secrets.token_hex(64)
        sps_cfg = None
        e_secret = _mint_e_secret() if sps_active else None
        sps_registered = False
        egress_pid = egress_port = None
        log_path = _tool_log_path(tool_def)
        running = RunningTool(tool_def.id, tool_def.port, self.backend, "",
                              log_path=str(log_path), boot_id=_boot_id(),
                              e_secret=e_secret, channel_secret=channel_secret)

        def mark_reaped():
            nonlocal running
            running = replace(running, process_exited=True)

        try:
            if sps_active:
                try:
                    sps_cfg = _resolve_sps(sps_env_path)
                    _sps_register(tool_def, e_secret, sps_cfg)
                    sps_registered = True
                except RunnerConfigError:
                    # Configuration errors must not degrade to secretless launch.
                    raise
                except Exception as exc:
                    if tool_def.secrets:
                        raise RuntimeError(
                            f"SPS register {tool_def.id} failed and the tool declares "
                            f"secrets; refusing to launch it secretless: {exc}"
                        ) from exc
                    log.warning("SPS register %s failed: %s (tool declares no secrets; "
                                "continuing without SPS)", tool_def.id, exc)
                    e_secret = None
                    sps_registered = False
            running = replace(running, e_secret=e_secret,
                              sps_host=sps_cfg.sp_host if sps_cfg else _DEFAULT_SPS_HOST,
                              sps_port=sps_cfg.sp_port if sps_cfg else _DEFAULT_SPS_PORT,
                              sps_ca=sps_cfg.sp_tls_ca if sps_cfg else None)
            policy = self._policy(tool_def)
            if policy.egress.allow:
                egress_pid, egress_port = _start_egress_proxy(policy.egress.allow)
                running = replace(running, egress_pid=egress_pid)
                running = replace(running, egress_identity=_process_identity(egress_pid))
            env = {
                **_child_environment(),
                "TOOLSTACK_PORT": str(tool_def.port),
                "TOOLSTACK_TOOL_CONFIG": str(tool_def.path / "toolyard.toml"),
            }
            env.pop("TOOLSTACK_E_SECRET", None)
            env["TOOLSTACK_CHANNEL_SECRET"] = channel_secret
            if e_secret is not None:
                env["TOOLSTACK_E_SECRET"] = e_secret
                env["TOOLSTACK_SPS_HOST"] = sps_cfg.sp_host
                env["TOOLSTACK_SPS_PORT"] = str(sps_cfg.sp_port)
                env["TOOLSTACK_SPS_CA"] = sps_cfg.sp_tls_ca
                env["TOOLSTACK_SPS_VERIFY"] = "1" if sps_cfg.verify else "0"
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
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            os.fchmod(log_fd, 0o600)
            try:
                pid = os.posix_spawn(
                    executable, argv, env, setpgroup=0,
                    file_actions=[(os.POSIX_SPAWN_DUP2, log_fd, 1),
                                  (os.POSIX_SPAWN_DUP2, log_fd, 2),
                                  (os.POSIX_SPAWN_CLOSE, log_fd)],
                )
                running = replace(running, handle=str(pid))
                running = replace(running, process_identity=_process_identity(pid))
            finally:
                os.close(log_fd)
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running, _on_reaped=mark_reaped):
                raise RuntimeError(f"tool {tool_def.id} exited immediately on start: see {log_path}")
            log.info("started tool %s on 127.0.0.1:%s (pid %s, log %s, sps=%s)",
                     tool_def.id, tool_def.port, pid, log_path, sps_registered)
            return running
        except BaseException as cause:
            try:
                _cleanup_partial_start(running)
            except RunnerStartCleanupError as cleanup:
                raise cleanup from cause
            finally:
                if sps_registered:
                    try:
                        _sps_unregister(tool_def.id, sps_env_path)
                    except Exception:
                        pass
            raise

    def stop(self, running: RunningTool) -> None:
        try:
            _cleanup_partial_start(running)
        finally:
            if running.e_secret:
                try:
                    _sps_unregister(
                        running.tool_id,
                        os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_SPS_ENV),
                    )
                except Exception:
                    log.warning("SPS unregister %s on stop failed", running.tool_id)
        log.info("stopped tool %s (pid %s)", running.tool_id, running.handle)

    def is_alive(self, running: RunningTool, *, _on_reaped=None) -> bool:
        if running.process_exited:
            return False
        if not running.handle:
            return False  # No main child spawned; stop still handles any helpers.
        pid = int(running.handle)
        current_boot = _boot_id()
        if running.boot_id and current_boot and running.boot_id != current_boot:
            return False
        current_identity = _process_identity(pid)
        if not running.boot_id or not current_boot:
            raise RunnerConfigError("process identity unknown; retain record")
        if (running.process_identity is not None and current_identity is not None
                and current_identity != running.process_identity):
            return False
        if not running.process_identity:
            if _pid_absent(pid):
                return False
            raise RunnerConfigError("process identity unknown; retain record")
        # Reap-aware liveness. The tool is our own posix_spawn child, so poll it with waitpid
        # first: on Linux a just-exited child that has not been reaped is a zombie whose pid still
        # answers killpg(pid, 0) as "alive", which would let start()'s readiness check pass a tool
        # that already crashed. waitpid(WNOHANG) reports (and reaps) the exit; (0, 0) means it is
        # still running. ChildProcessError means it is not ours to reap (already reaped, or a
        # handle carried across processes) -- fall back to the signal probe below.
        try:
            reaped, _ = os.waitpid(pid, os.WNOHANG)
            if reaped:
                if _on_reaped is not None:
                    _on_reaped()
                return False
            return True  # waitpid proved this is our current, live child
        except ChildProcessError:
            pass
        if _pid_absent(pid):
            return False
        if not _pids_are_current(running):
            raise RuntimeError("process identity unconfirmed; retain record")
        return True


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
def _netguard_argv(*args: str) -> list[str]:
    """Compatibility entry point: mutable privileged Python launch is disabled."""
    raise RunnerConfigError("Linux native runner disabled: mutable sudo Python helper is unsafe; no validated privileged helper")


@functools.lru_cache(maxsize=1)
def _bwrap_usable() -> bool:
    """Disabled; never probe sudo or modify host network/cgroups."""
    return False


class BwrapRunner:
    """Disabled Linux-native API, retained to diagnose legacy records honestly."""

    backend = "bwrap"

    def _policy(self, tool_def: ToolDef) -> SandboxPolicy:
        return SandboxPolicy(egress=EgressPolicy(allow=tuple(tool_def.egress)))

    def _cgroup_procs(self, tool_id: str) -> str:
        return f"{_CGROUP_ROOT}/{_NETGUARD_PARENT}/{tool_id}/cgroup.procs"

    def start(self, tool_def: ToolDef) -> RunningTool:
        raise RunnerConfigError("Linux native runner disabled: no validated privileged helper")

    def stop(self, running: RunningTool) -> None:
        raise RunnerConfigError(f"Linux native runner disabled; retain legacy record {running.tool_id}; operator cleanup required")

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
        if tool_def.secrets or os.environ.get("TOOLSTACK_E_SECRET") or (
                os.environ.get("TOOLSTACK_SPS_SKIP") != "1" and
                os.path.exists(os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_SPS_ENV))):
            raise RunnerConfigError("docker + SPS lifecycle is not validated")
        channel_secret = _secrets.token_hex(64)
        name = None
        log_pid = None
        log_path = _tool_log_path(tool_def)
        running = RunningTool(tool_def.id, tool_def.port, self.backend, "",
                              channel_secret=channel_secret, boot_id=_boot_id(),
                              log_path=str(log_path))

        def log_spawned(pid):
            nonlocal running
            # Keep the handle even if identity capture or closing the log fails.
            running = replace(running, log_pid=pid)
            running = replace(running, log_identity=_process_identity(pid))

        try:
            rest_generic = tool_def.type == "rest" and tool_def.image is None
            image = tool_def.image or ("python:3.13-slim" if rest_generic else f"toolstack-{tool_def.id}")
            if tool_def.image is None and not rest_generic:
                bundled = tool_def.path.resolve() in {
                    (_REPO_ROOT / "tools" / "echo_api").resolve(),
                    (_REPO_ROOT / "tools" / "echo_mcp").resolve()}
                context = _REPO_ROOT if bundled else tool_def.path
                self._docker(["build", "-t", image, "-f", str(tool_def.path / "Dockerfile"),
                              str(context)], _DOCKER_BUILD_TIMEOUT, check=True)
            name = f"toolyard-{tool_def.id}"
            running = replace(running, handle=name)
            self._docker(["rm", "-f", name], _DOCKER_RM_TIMEOUT)  # clear a same-named leftover
            run_args = [
                "run", "-d", "--name", name,
                "-p", f"127.0.0.1:{tool_def.port}:{tool_def.port}",
                "-e", f"TOOLSTACK_PORT={tool_def.port}",
                "-e", f"TOOLSTACK_CHANNEL_SECRET={channel_secret}",
                "-e", "TOOLSTACK_BIND=0.0.0.0",  # container-internal; host side stays loopback via -p
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
            run_args.append(image)
            if rest_generic:
                run_args += ["python3", "-m", "toolstack_forwarder"]
            self._docker(run_args, _DOCKER_RUN_TIMEOUT, check=True)
            log_pid = _start_docker_log_follower(name, log_path, _on_spawn=log_spawned)
            if running.log_pid != log_pid:
                log_spawned(log_pid)
            time.sleep(_READINESS_WAIT)
            if not self.is_alive(running):
                raise RuntimeError(f"tool {tool_def.id} container exited immediately: see {log_path}")
            log.info("started tool %s in container %s on :%s (log %s)",
                     tool_def.id, name, tool_def.port, log_path)
            return running
        except BaseException as cause:
            removed = True
            if name:
                try:
                    removal = subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                                             timeout=_DOCKER_RM_TIMEOUT)
                    removed = removal.returncode == 0
                except BaseException:
                    removed = False
            try:
                running = _cleanup_partial_start(running)
            except RunnerStartCleanupError as cleanup:
                raise cleanup from cause
            if not removed:
                raise RunnerStartCleanupError(running) from cause
            raise

    def stop(self, running: RunningTool) -> None:
        cleanup_error = None
        try:
            running = _cleanup_partial_start(running)
        except RunnerStartCleanupError as exc:
            cleanup_error = exc
            running = exc.running
        try:
            r = subprocess.run(["docker", "rm", "-f", running.handle],
                               capture_output=True, text=True, timeout=_DOCKER_RM_TIMEOUT)
            if r.returncode != 0:
                raise RuntimeError(f"docker removal failed for {running.handle}; retain state record")
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
            raise RunnerStartCleanupError(running) from exc
        if cleanup_error:
            raise cleanup_error
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
