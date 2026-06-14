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
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import ToolDef


@dataclass(frozen=True)
class RunningTool:
    tool_id: str
    port: int
    backend: str
    handle: str  # pid (process) or container name (docker)
    workdir: str  # secrets dir to clean up on stop


def _write_secrets(tool_id: str, secrets: dict[str, str]) -> str:
    secrets_dir = tempfile.mkdtemp(prefix=f"toolyard-{tool_id}-")
    for name, value in secrets.items():
        path = Path(secrets_dir) / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
    return secrets_dir


class ProcessRunner:
    backend = "process"

    def start(self, tool_def: ToolDef, secrets: dict[str, str]) -> RunningTool:
        if not tool_def.command:
            raise ValueError(f"tool {tool_def.id} has no entrypoint.command")
        secrets_dir = _write_secrets(tool_def.id, secrets)
        env = {
            **os.environ,
            "TOOLSTACK_SECRETS_DIR": secrets_dir,
            "TOOLSTACK_PORT": str(tool_def.port),
        }
        # posix_spawn (not Popen) so the detached child has no lifecycle object to
        # warn about; setpgroup=0 gives it its own group so stop() can killpg it.
        script = f"cd {shlex.quote(str(tool_def.path))} && exec {tool_def.command}"
        pid = os.posix_spawn("/bin/sh", ["/bin/sh", "-c", script], env, setpgroup=0)
        return RunningTool(tool_def.id, tool_def.port, self.backend, str(pid), secrets_dir)

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
        shutil.rmtree(running.workdir, ignore_errors=True)

    def is_alive(self, running: RunningTool) -> bool:
        try:
            os.killpg(int(running.handle), 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False


class DockerRunner:
    backend = "docker"

    def start(self, tool_def: ToolDef, secrets: dict[str, str]) -> RunningTool:
        secrets_dir = _write_secrets(tool_def.id, secrets)
        image = tool_def.image or f"toolstack-{tool_def.id}"
        if tool_def.image is None:
            subprocess.run(["docker", "build", "-t", image, str(tool_def.path)], check=True)
        name = f"toolyard-{tool_def.id}"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(
            [
                "docker", "run", "-d", "--name", name,
                "-p", f"127.0.0.1:{tool_def.port}:{tool_def.port}",
                "-e", f"TOOLSTACK_PORT={tool_def.port}",
                "-e", "TOOLSTACK_BIND=0.0.0.0",  # container-internal; host side stays loopback via -p
                "-v", f"{secrets_dir}:/run/secrets:ro",
                image,
            ],
            check=True,
        )
        return RunningTool(tool_def.id, tool_def.port, self.backend, name, secrets_dir)

    def stop(self, running: RunningTool) -> None:
        subprocess.run(["docker", "rm", "-f", running.handle], capture_output=True)
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
