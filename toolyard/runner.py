"""Tool runners.

`ProcessRunner` (dev/CI, zero infra) starts the tool as a local subprocess with
its secrets written to a private 0700 dir, pointed at by `$TOOLSTACK_SECRETS_DIR`.
`DockerRunner` (production) runs the tool in a container with its secrets mounted
at `/run/secrets`. Both keep secret values entirely off the broker.

On stop, the secrets dir is removed. (Hardening note: production should inject
secrets into a container tmpfs at start so they never touch host disk; the bind
mount here is the simple Phase 2 form.)
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import ToolDef

# Container-internal mount point for the writable-secret socket (message-contracts
# §4); matches the tool's default TOOLYARD_SECRETS_SOCKET.
_CONTAINER_SOCKET = "/run/toolyard/secrets.sock"
_REPO_ROOT = Path(__file__).resolve().parents[1]  # so `-m toolyard.write_proxy` imports


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
    for name, value in secrets.items():
        path = Path(secrets_dir) / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
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
        secrets_dir = _write_secrets(tool_def.id, secrets)
        proxy_pid, proxy_dir = _start_write_proxy(tool_def, secret_backend, secrets_file)
        env = {
            **os.environ,
            "TOOLSTACK_SECRETS_DIR": secrets_dir,
            "TOOLSTACK_PORT": str(tool_def.port),
        }
        if proxy_dir:
            env["TOOLYARD_SECRETS_SOCKET"] = str(Path(proxy_dir) / "secrets.sock")
        # posix_spawn (not Popen) so the detached child has no lifecycle object to
        # warn about; setpgroup=0 gives it its own group so stop() can killpg it.
        script = f"cd {shlex.quote(str(tool_def.path))} && exec {tool_def.command}"
        pid = os.posix_spawn("/bin/sh", ["/bin/sh", "-c", script], env, setpgroup=0)
        return RunningTool(tool_def.id, tool_def.port, self.backend, str(pid), secrets_dir,
                           proxy_pid, proxy_dir)

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

    def is_alive(self, running: RunningTool) -> bool:
        try:
            os.killpg(int(running.handle), 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False


class DockerRunner:
    backend = "docker"

    def start(self, tool_def: ToolDef, secrets: dict[str, str], *,
              secret_backend: str | None = None, secrets_file: str | None = None) -> RunningTool:
        secrets_dir = _write_secrets(tool_def.id, secrets)
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
        image = tool_def.image or f"toolstack-{tool_def.id}"
        if tool_def.image is None:
            subprocess.run(["docker", "build", "-t", image, str(tool_def.path)], check=True)
        name = f"toolyard-{tool_def.id}"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        cmd = [
            "docker", "run", "-d", "--name", name,
            "-p", f"127.0.0.1:{tool_def.port}:{tool_def.port}",
            "-e", f"TOOLSTACK_PORT={tool_def.port}",
            "-e", "TOOLSTACK_BIND=0.0.0.0",  # container-internal; host side stays loopback via -p
            "-v", f"{secrets_dir}:/run/secrets:ro",
        ]
        if proxy_dir:
            # Mount the proxy's socket dir so the tool reaches it at the contract path.
            cmd += ["-v", f"{proxy_dir}:/run/toolyard",
                    "-e", f"TOOLYARD_SECRETS_SOCKET={_CONTAINER_SOCKET}"]
        cmd.append(image)
        subprocess.run(cmd, check=True)
        return RunningTool(tool_def.id, tool_def.port, self.backend, name, secrets_dir,
                           proxy_pid, proxy_dir)

    def stop(self, running: RunningTool) -> None:
        subprocess.run(["docker", "rm", "-f", running.handle], capture_output=True)
        _stop_proxy(running)
        shutil.rmtree(running.workdir, ignore_errors=True)

    def is_alive(self, running: RunningTool) -> bool:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", running.handle],
            capture_output=True, text=True,
        )
        return result.stdout.strip() == "true"


def get_runner(backend: str):
    if backend == "process":
        return ProcessRunner()
    if backend == "docker":
        return DockerRunner()
    raise ValueError(f"unknown runner backend: {backend}")
