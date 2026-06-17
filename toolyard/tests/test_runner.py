"""Runner end-to-end: the toolyard starts the real echo tool with its secret, and
the broker's real HttpRuntime forwards calls to it. Proves the Phase 2 property:
the broker reaches a real tool on 127.0.0.1:port, the tool reads its own secret,
and the secret value never flows back through the broker.

The process backend needs no Docker. A docker-backed version is opt-in via
TOOLSTACK_TEST_DOCKER=1.
"""

import dataclasses
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import tomllib
import unittest
from pathlib import Path

from broker.registry import ToolOp
from broker.runtime import HttpRuntime
from toolyard.config import load
from toolyard.runner import DockerRunner, ProcessRunner

REPO = Path(__file__).resolve().parents[2]
TOOL_TOML = REPO / "tools" / "echo_rest" / "toolyard.toml"
SECRET = "dev-secret-123"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_tool(port: int, tries: int = 80) -> bool:
    # An HTTP probe, not a bare TCP connect: with the docker backend the proxy
    # accepts connections before the container app is ready, so readiness means a
    # real response, not just an open socket.
    for _ in range(tries):
        try:
            _call(port, "say", {})
            return True
        except Exception:
            time.sleep(0.25)
    return False


def _call(port, op, arguments, request_id=1, caller="hermes"):
    return HttpRuntime().execute(ToolOp("echo", op, "low", port, "rest"),
                                 arguments, request_id, caller)


class ProcessRunnerE2E(unittest.TestCase):
    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool, {"api_key": SECRET})
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("echo tool did not start")

    def test_broker_forwards_and_tool_reads_its_secret(self):
        self.assertEqual(_call(self.tool.port, "say", {"m": "hi"}), {"echoed": {"m": "hi"}})

        status = _call(self.tool.port, "secret_status", {})
        self.assertTrue(status["has_api_key"])
        self.assertEqual(status["api_key_len"], len(SECRET))
        # the secret VALUE never comes back through the broker's runtime
        self.assertNotIn(SECRET, json.dumps(status))

    def test_tool_sees_broker_context(self):
        who = _call(self.tool.port, "whoami", {}, request_id=99, caller="hermes")
        self.assertEqual(who["caller"], "hermes")
        self.assertEqual(who["broker_request_id"], 99)

    def test_stop_removes_the_secrets_dir(self):
        workdir = Path(self.running.workdir)
        self.assertTrue((workdir / "api_key").exists())
        self.runner.stop(self.running)
        self.assertFalse(workdir.exists())


class SharedSecretE2E(unittest.TestCase):
    """Opt-in broker->tool shared secret (T-022): with a broker_secret provisioned, the
    echo tool accepts a call carrying the matching X-Toolstack-Secret header and rejects
    one that is missing or wrong (the tool's 401 surfaces as a RuntimeError from the
    runtime, which the request lifecycle maps to 502)."""

    SHARED = "broker-shh-456"

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(
            self.tool, {"api_key": SECRET, "broker_secret": self.SHARED})
        self.addCleanup(self.runner.stop, self.running)
        if not self._ready():
            self.fail("echo tool did not start")

    def _signed_call(self, secret, op="say", arguments=None):
        rt = HttpRuntime(tool_secret=lambda tool_id: secret)
        return rt.execute(ToolOp("echo", op, "low", self.tool.port, "rest"),
                          arguments or {}, 1, "hermes")

    def _ready(self, tries: int = 80) -> bool:
        # readiness means a correctly-signed call gets through (not just an open socket)
        for _ in range(tries):
            try:
                self._signed_call(self.SHARED)
                return True
            except Exception:
                time.sleep(0.25)
        return False

    def test_matching_secret_is_accepted(self):
        self.assertEqual(self._signed_call(self.SHARED, "say", {"m": "hi"}),
                         {"echoed": {"m": "hi"}})

    def test_missing_secret_is_rejected(self):
        with self.assertRaises(RuntimeError):  # no header -> tool 401
            self._signed_call(None, "say", {"m": "hi"})

    def test_wrong_secret_is_rejected(self):
        with self.assertRaises(RuntimeError):  # mismatched header -> tool 401
            self._signed_call("not-the-secret", "say", {"m": "hi"})


def _docker_ok() -> bool:
    if not os.environ.get("TOOLSTACK_TEST_DOCKER"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def _post_unix(socket_path: str, name: str, value: str) -> int:
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


@unittest.skipUnless(_docker_ok(), "set TOOLSTACK_TEST_DOCKER=1 with docker running")
class DockerRunnerE2E(unittest.TestCase):
    def test_container_serves_with_its_secret(self):
        tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        runner = DockerRunner()
        running = runner.start(tool, {"api_key": SECRET})
        self.addCleanup(runner.stop, running)
        self.assertTrue(_wait_for_tool(tool.port), "container did not start")
        status = _call(tool.port, "secret_status", {})
        self.assertTrue(status["has_api_key"])
        self.assertEqual(status["api_key_len"], len(SECRET))

    def test_stop_removes_the_container(self):
        tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        runner = DockerRunner()
        running = runner.start(tool, {"api_key": SECRET})
        self.addCleanup(runner.stop, running)  # idempotent if already stopped
        self.assertTrue(_wait_for_tool(tool.port), "container did not start")
        runner.stop(running)
        gone = subprocess.run(["docker", "ps", "-aq", "-f", f"name=^{running.handle}$"],
                              capture_output=True, text=True).stdout.strip()
        self.assertEqual(gone, "", "stop did not remove the container")
        self.assertFalse(Path(running.workdir).exists())  # secrets dir cleaned up

    def test_writable_tool_mounts_proxy_socket_and_patches_backend(self):
        # A tool with a writable secret: the docker runner starts the host-side write proxy
        # AND bind-mounts its socket dir into the container at /run/toolyard. Run a distinct
        # tool id (echowp, no container collision) FROM the reused echo image (image= in the
        # toml -> the runner skips its own build, so this leaves no throwaway/dangling image).
        subprocess.run(["docker", "build", "-t", "toolstack-echo", str(REPO / "tools" / "echo_rest")],
                       check=True, capture_output=True)
        d = Path(tempfile.mkdtemp(prefix="tsr-t012-"))
        self.addCleanup(shutil.rmtree, str(d), ignore_errors=True)
        (d / "toolyard.toml").write_text(
            'id = "echowp"\ntype = "rest"\n[entrypoint]\nport = 4601\nimage = "toolstack-echo"\n'
            '[[secrets]]\nname = "api_key"\nfield = "API_KEY"\nwritable = true\n')
        secrets_file = d / "secrets.toml"
        secrets_file.write_text('[echowp]\nAPI_KEY = "old"\n')

        tool = dataclasses.replace(load(d / "toolyard.toml"), port=_free_port())
        runner = DockerRunner()
        running = runner.start(tool, {"api_key": "old"},
                               secret_backend="file", secrets_file=str(secrets_file))
        self.addCleanup(runner.stop, running)
        self.assertTrue(_wait_for_tool(tool.port), "container did not start")

        # the write proxy was started, and the socket dir is bind-mounted into the container
        self.assertIsNotNone(running.proxy_pid)
        mounts = subprocess.run(["docker", "inspect", running.handle, "--format", "{{json .Mounts}}"],
                                capture_output=True, text=True).stdout
        self.assertIn("/run/toolyard", mounts)
        self.assertIn(running.proxy_dir, mounts)

        # the host-side proxy patches the file backend (the writeback round trip)
        sock = str(Path(running.proxy_dir) / "secrets.sock")
        self.assertEqual(_post_unix(sock, "api_key", "rotated"), 200)
        with secrets_file.open("rb") as f:
            self.assertEqual(tomllib.load(f)["echowp"]["API_KEY"], "rotated")


if __name__ == "__main__":
    unittest.main()
