"""Writable-secret proxy: the toolyard side of message-contracts §4."""

import json
import os
import shutil
import socket
import tempfile
import threading
import time
import tomllib
import unittest
from pathlib import Path

from toolyard.config import SecretSpec, ToolDef, load
from toolyard.runner import RunningTool, _start_write_proxy, _stop_proxy
from toolyard.secrets import FileBackend
from toolyard.write_proxy import serve


def _tool(*secrets: SecretSpec) -> ToolDef:
    return ToolDef(id="demo", type="api", port=1, command=None, image=None,
                   secrets=tuple(secrets), path=Path("."))


def _post(socket_path: str, name: str, value: str) -> int:
    body = json.dumps({"value": value, "reason": "test"}).encode()
    req = (f"POST /v1/secrets/{name} HTTP/1.1\r\nHost: toolyard\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    sock.sendall(req)
    raw = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return int(raw.split()[1])


class WriteProxy(unittest.TestCase):
    def setUp(self):
        self.secrets_file = Path(tempfile.mkdtemp()) / "secrets.toml"
        self.secrets_file.write_text('[demo]\nTOKEN = "old"\n')
        self.backend = FileBackend(self.secrets_file)
        self.tool = _tool(SecretSpec("token", "TOKEN", writable=True),
                          SecretSpec("ro", "RO", writable=False))
        self.sock_path = str(Path(tempfile.mkdtemp()) / "secrets.sock")
        self.server = serve(self.sock_path, self.tool, self.backend)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_writable_secret_is_patched_to_backend(self):
        self.assertEqual(_post(self.sock_path, "token", "new-value"), 200)
        with self.secrets_file.open("rb") as f:
            self.assertEqual(tomllib.load(f)["demo"]["TOKEN"], "new-value")

    def test_non_writable_secret_is_forbidden(self):
        self.assertEqual(_post(self.sock_path, "ro", "x"), 403)

    def test_unknown_secret_is_not_found(self):
        self.assertEqual(_post(self.sock_path, "nope", "x"), 404)


def _pid_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)  # pgid == pid (the proxy is spawned setpgroup=0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


class WriteProxyThroughRunner(unittest.TestCase):
    """The runner integration (`_start_write_proxy` / `_stop_proxy`), not just `serve()`
    in-process: a tool with a writable secret gets a real proxy subprocess whose socket a
    tool can POST to, and stopping it tears the process + socket dir down. This exercises
    the toolyard-writeback path end to end on the process runner (no Docker)."""

    def _write_tool(self, *, writable: bool) -> "ToolDef":
        d = Path(tempfile.mkdtemp(prefix="tsr-t011-"))
        self.addCleanup(shutil.rmtree, str(d), ignore_errors=True)
        toml = ('id = "demo"\ntype = "api"\n[entrypoint]\nport = 4601\ncommand = "true"\n'
                '[[secrets]]\nname = "token"\nfield = "TOKEN"\n'
                f'writable = {"true" if writable else "false"}\n')
        (d / "toolyard.toml").write_text(toml)
        return load(d / "toolyard.toml")

    def test_runner_starts_proxy_patches_backend_and_stop_cleans_up(self):
        tool = self._write_tool(writable=True)
        secrets_dir = tempfile.mkdtemp(prefix="tsr-t011-sec-")
        self.addCleanup(shutil.rmtree, secrets_dir, ignore_errors=True)
        secrets_file = Path(secrets_dir) / "secrets.toml"
        secrets_file.write_text('[demo]\nTOKEN = "old"\n')

        proxy_pid, proxy_dir = _start_write_proxy(tool, "file", str(secrets_file))
        self.assertIsNotNone(proxy_pid)
        self.assertIsNotNone(proxy_dir)
        # `handle` is the tool's process pid; in this test we never spawn the tool itself
        # (only the write proxy), so `handle` is not used for any kill. Use an obvious
        # non-numeric sentinel so that, if a future test starts passing `handle` through a
        # `_terminate(pid)` path, `int(...)` raises ValueError instead of silently calling
        # `os.killpg(0, ...)` (signals the caller's process group) or `os.killpg(1, ...)`
        # (signals init). Belt-and-suspenders for the "kill pid 1" footgun.
        running = RunningTool(tool_id="demo", port=4601, backend="process", handle="unused",
                              workdir=str(secrets_file.parent),
                              proxy_pid=proxy_pid, proxy_dir=proxy_dir)
        self.addCleanup(_stop_proxy, running)  # never leak the subprocess if we fail

        sock = Path(proxy_dir) / "secrets.sock"
        for _ in range(120):  # ≤6s for a cold interpreter to import + bind (loaded CI)
            if sock.exists():
                break
            time.sleep(0.05)
        self.assertTrue(sock.exists(), "proxy did not bind its socket")

        # a tool writes a new value through the runner-started proxy -> the backend is patched
        self.assertEqual(_post(str(sock), "token", "rotated"), 200)
        with secrets_file.open("rb") as f:
            self.assertEqual(tomllib.load(f)["demo"]["TOKEN"], "rotated")

        # stop tears down the process group and removes the socket dir
        _stop_proxy(running)
        self.assertFalse(Path(proxy_dir).exists())
        self.assertFalse(_pid_alive(int(proxy_pid)), "proxy process survived stop")

    def test_no_proxy_when_no_writable_secret(self):
        tool = self._write_tool(writable=False)
        proxy_pid, proxy_dir = _start_write_proxy(tool, "file", None)
        self.assertEqual((proxy_pid, proxy_dir), (None, None))


if __name__ == "__main__":
    unittest.main()
