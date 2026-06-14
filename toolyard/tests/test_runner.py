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
import socket
import subprocess
import time
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


def _docker_ok() -> bool:
    if not os.environ.get("TOOLSTACK_TEST_DOCKER"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


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


if __name__ == "__main__":
    unittest.main()
