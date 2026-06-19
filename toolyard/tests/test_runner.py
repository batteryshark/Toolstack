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
import threading
import time
import tomllib
import unittest
import urllib.request
from pathlib import Path

from broker.identity import hash_token
from broker.registry import Registry, ToolOp
from broker.runtime import HttpRuntime
from broker.server import build_server
from toolyard.config import load
from toolyard.runner import DockerRunner, ProcessRunner

REPO = Path(__file__).resolve().parents[2]
TOOL_TOML = REPO / "tools" / "echo_rest" / "toolyard.toml"
TOOL_MCP_TOML = REPO / "tools" / "echo_mcp" / "toolyard.toml"
TOOL_REST_TOML = REPO / "tools" / "rest_kv" / "toolyard.toml"
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
    return HttpRuntime().execute(ToolOp("echo", op, "low", port, "api"),
                                 arguments, request_id, caller)


def _mcp_call(port, op, arguments, request_id=1, caller="hermes"):
    return HttpRuntime().execute(ToolOp("echo-mcp", op, "read", port, "mcp"),
                                 arguments, request_id, caller)


def _wait_for_mcp_tool(port: int, tries: int = 80) -> bool:
    for _ in range(tries):
        try:
            _mcp_call(port, "say", {})
            return True
        except Exception:
            time.sleep(0.25)
    return False


def _rest_call(port, verb, arguments, request_id=1, caller="hermes"):
    return HttpRuntime().execute(ToolOp("kv", verb, "read", port, "rest"),
                                 arguments, request_id, caller)


def _wait_for_rest_tool(port: int, tries: int = 80) -> bool:
    for _ in range(tries):
        try:
            _rest_call(port, "GET", {"path": "/items"})
            return True
        except Exception:
            time.sleep(0.25)
    return False


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
        return rt.execute(ToolOp("echo", op, "low", self.tool.port, "api"),
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


class McpOverHttpE2E(unittest.TestCase):
    """T-021 AC#4: a real MCP JSON-RPC frame over HTTP -> real broker (/mcp) -> real echo
    tool process -> response. The broker terminates MCP, applies policy/audit, and forwards
    through the same REST runtime that the /v1/actions path uses. No Docker needed."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool, {"api_key": SECRET})
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("echo tool did not start")

        # a real broker whose registry forwards echo.say to the running tool's port
        registry = Registry({"echo": {"port": self.tool.port, "type": "api",
                                      "ops": {"say": {"risk": "read", "description": "", "args": []}}}})
        self.server = build_server(port=0, db_path=":memory:", audit_sink=None, registry=registry)
        store = self.server.ctx.store
        caller_id = store.add_caller("hermes")
        self.token = "mcp-e2e-token"
        store.add_token(caller_id, hash_token(self.token))
        store.set_policy(caller_id, {"tools": {"echo": {"say": "allow"}}})
        self.bport = self.server.server_address[1]
        self.bthread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.bthread.start()
        self.addCleanup(self._stop_broker)

    def _stop_broker(self):
        self.server.shutdown()
        self.bthread.join(timeout=5)
        self.server.server_close()
        self.server.ctx.store.close()

    def test_mcp_call_over_http_reaches_the_real_tool(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "echo__say", "arguments": {"m": "hi"}}}
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.bport}/mcp", data=json.dumps(msg).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())

        result = body["result"]
        self.assertFalse(result["isError"])
        inner = json.loads(result["content"][0]["text"])  # the broker's outcome body
        self.assertEqual(inner["status"], "ok")
        self.assertEqual(inner["result"], {"echoed": {"m": "hi"}})  # straight from the tool


class McpProcessRunnerE2E(unittest.TestCase):
    """The mcp transport end-to-end: the runner starts the real echo-mcp process (a
    streamable-HTTP MCP server) and the broker's MCP client reaches it via the same
    HttpRuntime.execute path the api tools use — proving type='mcp' works tool-to-broker
    with no Docker."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_MCP_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool, {})  # echo-mcp ships with no secrets
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_mcp_tool(self.tool.port):
            self.fail("echo-mcp tool did not start")

    def test_broker_calls_tool_over_mcp(self):
        result = _mcp_call(self.tool.port, "say", {"m": "hi"})
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], {"echoed": {"m": "hi"}})

    def test_tool_sees_broker_context_via_meta(self):
        result = _mcp_call(self.tool.port, "whoami", {}, request_id=99, caller="hermes")
        who = result["structuredContent"]
        self.assertEqual(who["caller"], "hermes")
        self.assertEqual(who["broker_request_id"], 99)


class RestProcessRunnerE2E(unittest.TestCase):
    """The rest transport end-to-end: the runner starts the real kv tool and the broker's
    verb-as-op passthrough drives a full CRUD cycle through HttpRuntime.execute — including a
    404 that passes through as data rather than raising. No Docker."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_REST_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool, {})  # kv ships with no secrets
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_rest_tool(self.tool.port):
            self.fail("kv tool did not start")

    def _call(self, verb, arguments):
        return _rest_call(self.tool.port, verb, arguments)

    def test_crud_cycle_through_the_passthrough(self):
        self.assertEqual(self._call("POST", {"path": "/items", "body": {"key": "x", "value": 1}})["status"], 201)
        got = self._call("GET", {"path": "/items/x"})
        self.assertEqual((got["status"], got["body"]), (200, {"key": "x", "value": 1}))
        self._call("PUT", {"path": "/items/x", "body": {"value": 2}})
        self.assertEqual(self._call("GET", {"path": "/items/x"})["body"]["value"], 2)
        self.assertEqual(self._call("DELETE", {"path": "/items/x"})["status"], 200)
        self.assertEqual(self._call("GET", {"path": "/items/x"})["status"], 404)  # gone now

    def test_missing_resource_404_passes_through_as_data(self):
        result = self._call("GET", {"path": "/items/ghost"})
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["body"]["error"], "not_found")


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
            'id = "echowp"\ntype = "api"\n[entrypoint]\nport = 4601\nimage = "toolstack-echo"\n'
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
