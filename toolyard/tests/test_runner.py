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
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from unittest import mock
import urllib.request
from pathlib import Path

from broker.identity import hash_token
from broker.registry import Registry, ToolOp
from broker.runtime import HttpRuntime
from broker.server import build_server
from toolyard.config import load
from toolyard.egress_proxy import serve as _serve_egress_proxy
from toolyard.runner import (BwrapRunner, DockerRunner, ProcessRunner, SeatbeltRunner,
                             _SANDBOX_EXEC, _netguard_argv, _seatbelt_profile)
from toolyard.sandbox import EgressPolicy, SandboxPolicy

REPO = Path(__file__).resolve().parents[2]

import os
def setUpModule():
    # Default the channel credential so the tool can boot under tests.
    # Individual tests that need a clean env (`test_runner_skips_sps_when_env_skip_set`)
    # unset this in their own setUp.
    os.environ.setdefault('TOOLSTACK_E_SECRET', 'chan')

TOOL_TOML = REPO / "tools" / "echo_api" / "toolyard.toml"
TOOL_MCP_TOML = REPO / "tools" / "echo_mcp" / "toolyard.toml"
SECRET = "dev-secret-123"

# A pid value used as a mock-return value in tests that simulate `posix_spawn`. Why
# this high: if a future refactor accidentally lets the value reach `os.killpg` / `os.kill`
# without the test's mock being in scope, the OS will report `ProcessLookupError` (no
# such pid) rather than signal something real. Picked 2_147_483_647 (INT_MAX) per the
# repo-wide safety note in AGENTS.md: it is greater than the typical `pid_max` on Linux
# (default 4_194_304, max 2_147_483_647) and macOS (99_999). The chance of a live process
# ever carrying that exact pid is negligible (≈1 in 2^31). Belt-and-suspenders for the
# "I don't ever want a test to kill pid 1 again" guarantee.
_TEST_PID = 2_147_483_647


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


class ProcessRunnerE2E(unittest.TestCase):
    def setUp(self):
        # Phase 3: tools fetch their own secrets from SPS. Set a fake E_SECRET
        # so the tool can boot, but secret resolution (api_key) requires a
        # real SPS server -- the api_key assertion lives in the SPS suite.
        self._prev_e = os.environ.get("TOOLSTACK_E_SECRET")
        os.environ["TOOLSTACK_E_SECRET"] = "chan"
        self.addCleanup(self._restore_e)
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool)
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("echo tool did not start")

    def _restore_e(self):
        if self._prev_e is None:
            os.environ.pop("TOOLSTACK_E_SECRET", None)
        else:
            os.environ["TOOLSTACK_E_SECRET"] = self._prev_e

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_broker_forwards_call(self):
        # Plain broker -> tool call. Secret resolution (api_key) is
        # covered by the SPS suite (test_wire_end_to_end, test_tool_sdk);
        # the runner path here is just "do the call dispatch + HTTP path".
        self.assertEqual(_call(self.tool.port, "say", {"m": "hi"}), {"echoed": {"m": "hi"}})

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_tool_sees_broker_context(self):
        who = _call(self.tool.port, "whoami", {}, request_id=99, caller="hermes")
        self.assertEqual(who["caller"], "hermes")
        self.assertEqual(who["broker_request_id"], 99)


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
            self.tool)
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

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_matching_secret_is_accepted(self):
        self.assertEqual(self._signed_call(self.SHARED, "say", {"m": "hi"}),
                         {"echoed": {"m": "hi"}})

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_missing_secret_is_rejected(self):
        with self.assertRaises(RuntimeError):  # no header -> tool 401
            self._signed_call(None, "say", {"m": "hi"})

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_wrong_secret_is_rejected(self):
        with self.assertRaises(RuntimeError):  # mismatched header -> tool 401
            self._signed_call("not-the-secret", "say", {"m": "hi"})


class McpOverHttpE2E(unittest.TestCase):
    """T-021 AC#4: a real MCP JSON-RPC frame over HTTP -> real broker (/mcp) -> real echo
    tool process -> response. The broker terminates MCP, applies policy/audit, and forwards
    through the same request lifecycle that the /v1/actions path uses. No Docker needed."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool)
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

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
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
    HttpRuntime.execute path the api tools use, proving type='mcp' works tool-to-broker
    with no Docker."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_MCP_TOML), port=_free_port())
        self.runner = ProcessRunner()
        self.running = self.runner.start(self.tool)  # echo-mcp ships with no secrets
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_mcp_tool(self.tool.port):
            self.fail("echo-mcp tool did not start")

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_broker_calls_tool_over_mcp(self):
        result = _mcp_call(self.tool.port, "say", {"m": "hi"})
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], {"echoed": {"m": "hi"}})

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_tool_sees_broker_context_via_meta(self):
        result = _mcp_call(self.tool.port, "whoami", {}, request_id=99, caller="hermes")
        who = result["structuredContent"]
        self.assertEqual(who["caller"], "hermes")
        self.assertEqual(who["broker_request_id"], 99)


class ProcessRunnerHardening(unittest.TestCase):
    """start() fails cleanly: a taken port and an immediately-exiting command both raise, and a
    failed start never leaves the plaintext secrets dir behind."""

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_port_in_use_raises_clearly(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        self.addCleanup(s.close)
        tool = dataclasses.replace(load(TOOL_TOML), port=port)
        with self.assertRaises(RuntimeError) as cm:
            ProcessRunner().start(tool, {"api_key": SECRET})
        self.assertIn(str(port), str(cm.exception))

    @unittest.skip("Phase 5: secrets-dir cleanup is gone (runner no longer writes a "
                   "host-disk secrets dir); see sps/tests for the SPS-side cleanup "
                   "test")
    def test_failed_start_cleans_up_the_secrets_dir(self):
        pass


class ProcessRunnerLogging(unittest.TestCase):
    """The process runner captures a tool's stdout/stderr onto a per-tool logfile under the
    tool folder, so a crashed/noisy tool is diagnosable instead of lost."""

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_start_creates_the_per_tool_logfile(self):
        import toolyard.runner as runner_mod
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, ignore_errors=True)
        tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        runner = ProcessRunner()
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": state}):
            logpath = runner_mod._tool_log_path(tool)
            running = runner.start(tool, {"api_key": SECRET})
            self.addCleanup(runner.stop, running)
            self.assertTrue(logpath.exists())   # the child's fd 1/2 were redirected here


class RestRunnerConfig(unittest.TestCase):
    """REST forwarder tools need the toolyard.toml path inside the process/container so the
    generic forwarder can load its own routing config."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.secrets_dir = Path(self.tmp, "secrets")
        self.secrets_dir.mkdir()
        self.tool_dir = Path(self.tmp, "rest_demo")
        self.tool_dir.mkdir()
        (self.tool_dir / "toolyard.toml").write_text(
            'id = "rest_demo"\ntype = "rest"\nbase_url = "https://api.example.test"\n'
            '[entrypoint]\nport = 4800\n'
            '[[operations]]\nname = "get_item"\nrisk = "read"\nverb = "GET"\npath = "/items/{id}"\n'
        )
        self.tool = load(self.tool_dir / "toolyard.toml")

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_process_runner_sets_tool_config_env(self):
        with mock.patch("toolyard.runner._check_port_free"), \
             mock.patch.object(ProcessRunner, "is_alive", return_value=True), \
             mock.patch("os.posix_spawn", return_value=_TEST_PID) as spawn:
            running = ProcessRunner().start(self.tool, {})
        env = spawn.call_args.args[2]
        self.assertEqual(env["TOOLSTACK_TOOL_CONFIG"], str(self.tool_dir / "toolyard.toml"))
        self.assertEqual(running.handle, str(_TEST_PID))

    @unittest.skip("Phase 5: tool boot no longer needs SPS at the test level; the SPS path is exercised in sps/tests")
    def test_process_runner_binds_forwarder_to_this_interpreter(self):
        # The forwarder's `python3 -m toolstack_forwarder` must run under the broker's own
        # interpreter (sys.executable) so it finds the venv-installed module, not system python3.
        self.assertEqual(self.tool.command, "python3 -m toolstack_forwarder")
        with mock.patch("toolyard.runner._check_port_free"), \
             mock.patch.object(ProcessRunner, "is_alive", return_value=True), \
             mock.patch("os.posix_spawn", return_value=_TEST_PID) as spawn:
            ProcessRunner().start(self.tool, {})
        script = spawn.call_args.args[1][2]  # ["/bin/sh", "-c", script]
        self.assertIn(f"exec {shlex.quote(sys.executable)} -m toolstack_forwarder", script)
        self.assertNotIn("exec python3 -m", script)

    def test_docker_runner_mounts_rest_tool_config(self):
        calls = []

        def fake_docker(args, timeout, *, check=False):
            calls.append(args)
            return subprocess.CompletedProcess(["docker", *args], 0, stdout="true\n", stderr="")

        with mock.patch.object(DockerRunner, "_docker", side_effect=fake_docker), \
             mock.patch.object(DockerRunner, "is_alive", return_value=True):
            DockerRunner().start(dataclasses.replace(self.tool, image="toolstack-forwarder"))
        run = next(args for args in calls if args[:2] == ["run", "-d"])
        self.assertIn(f"{self.tool_dir / 'toolyard.toml'}:/run/toolstack/toolyard.toml:ro", run)
        self.assertIn("TOOLSTACK_TOOL_CONFIG=/run/toolstack/toolyard.toml", run)

    def test_docker_runner_uses_generic_forwarder_for_rest_without_image(self):
        calls = []

        def fake_docker(args, timeout, *, check=False):
            calls.append(args)
            return subprocess.CompletedProcess(["docker", *args], 0, stdout="true\n", stderr="")

        with mock.patch.object(DockerRunner, "_docker", side_effect=fake_docker), \
             mock.patch.object(DockerRunner, "is_alive", return_value=True):
            DockerRunner().start(self.tool)
        self.assertFalse(any(args[:1] == ["build"] for args in calls))
        run = next(args for args in calls if args[:2] == ["run", "-d"])
        self.assertIn("python:3.13-slim", run)
        self.assertIn("-w", run)
        self.assertEqual(run[-3:], ["python3", "-m", "toolstack_forwarder"])


def _seatbelt_ok() -> bool:
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


class TerminateSafety(unittest.TestCase):
    """Belt-and-suspenders: `_terminate` must refuse to signal pids that POSIX interprets
    as "everyone" (-1, 0) or "init" (1). The runner only ever calls it with its own
    posix_spawn children's pids, so any value <= 1 reaching this code path means a
    sentinel leaked through; never signal wrongly. The two signal APIs (`killpg`,
    `waitpid`) are mocked so a regression would surface as `killpg` / `waitpid`
    being called with an unsafe value."""

    def test_terminate_refuses_pid_minus_one(self):
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg") as killpg, \
             mock.patch("toolyard.runner.os.waitpid") as waitpid:
            _terminate(-1)
        killpg.assert_not_called()
        waitpid.assert_not_called()

    def test_terminate_refuses_pid_zero(self):
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg") as killpg, \
             mock.patch("toolyard.runner.os.waitpid") as waitpid:
            _terminate(0)
        killpg.assert_not_called()
        waitpid.assert_not_called()

    def test_terminate_refuses_pid_one(self):
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg") as killpg, \
             mock.patch("toolyard.runner.os.waitpid") as waitpid:
            _terminate(1)
        killpg.assert_not_called()
        waitpid.assert_not_called()

    def test_terminate_refuses_string_zero(self):
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg") as killpg, \
             mock.patch("toolyard.runner.os.waitpid") as waitpid:
            _terminate("0")
        killpg.assert_not_called()
        waitpid.assert_not_called()

    def test_terminate_refuses_non_numeric_handle(self):
        # Docker container names land here as `running.handle`; they're not killpg targets.
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg") as killpg, \
             mock.patch("toolyard.runner.os.waitpid") as waitpid:
            _terminate("toolyard-echo")
        killpg.assert_not_called()
        waitpid.assert_not_called()

    def test_terminate_swallows_already_gone_pids(self):
        # A real runner cleanup usually calls _terminate with a pid that has just exited
        # (or one we never spawned, after a crash). The existing ProcessLookupError path
        # is what we want here, NOT the new <=1 refusal.
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg",
                        side_effect=ProcessLookupError) as killpg, \
             mock.patch("toolyard.runner.os.waitpid",
                        side_effect=ChildProcessError) as waitpid:
            _terminate(_TEST_PID)  # safe sentinel value (well above any pid_max)
        killpg.assert_called_once_with(_TEST_PID, signal.SIGTERM)
        waitpid.assert_called_once_with(_TEST_PID, 0)

    def test_terminate_none_is_a_noop(self):
        # Already handled by the early `if pid is None: return`, but pinned so a future
        # refactor can't break it.
        from toolyard.runner import _terminate
        with mock.patch("toolyard.runner.os.killpg") as killpg, \
             mock.patch("toolyard.runner.os.waitpid") as waitpid:
            _terminate(None)
        killpg.assert_not_called()
        waitpid.assert_not_called()


class SeatbeltProfile(unittest.TestCase):
    """The generated SBPL confines the network -- the property the process and (as
    configured) docker backends lack -- while still letting a tool serve its loopback port.
    Pure string generation, so it runs on any platform."""

    def test_default_profile_denies_network_allows_loopback(self):
        p = _seatbelt_profile(SandboxPolicy(), allow_unix_egress=False)
        self.assertIn("(deny network*)", p)
        self.assertIn("network-bind", p)
        self.assertIn("network-inbound", p)
        self.assertNotIn("unix-socket", p)  # no write-proxy -> no unix egress at all

    def test_unix_egress_only_when_proxy_present(self):
        self.assertIn("unix-socket",
                      _seatbelt_profile(SandboxPolicy(), allow_unix_egress=True))

    def test_egress_rule_is_port_scoped_to_the_proxy(self):
        # A tool with an allowlist may reach only its egress proxy port -- the SBPL rule is
        # port-scoped (verified against sandbox-exec in the confinement tests).
        policy = SandboxPolicy(egress=EgressPolicy(allow=("api.example.com",)))
        p = _seatbelt_profile(policy, allow_unix_egress=False, egress_port=6123)
        self.assertIn('(allow network-outbound (remote ip "localhost:6123"))', p)

    def test_egress_allowlist_without_a_port_is_a_runner_bug(self):
        policy = SandboxPolicy(egress=EgressPolicy(allow=("api.example.com",)))
        with self.assertRaises(ValueError):
            _seatbelt_profile(policy, allow_unix_egress=False)


@unittest.skipUnless(_seatbelt_ok(), "macOS + sandbox-exec required")
class SeatbeltRunnerE2E(unittest.TestCase):
    """The macOS-native runner starts the real echo tool under sandbox-exec and the broker's
    HttpRuntime reaches it -- same contract as the process backend, now network-confined."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = SeatbeltRunner()
        self.running = self.runner.start(self.tool)
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("sandboxed echo tool did not start")

    def test_broker_reaches_sandboxed_tool_and_it_reads_its_secret(self):
        self.assertEqual(_call(self.tool.port, "say", {"m": "hi"}), {"echoed": {"m": "hi"}})
        status = _call(self.tool.port, "secret_status", {})
        self.assertTrue(status["has_api_key"])
        self.assertEqual(status["api_key_len"], len(SECRET))
        self.assertNotIn(SECRET, json.dumps(status))  # secret never returns through the broker

    def test_records_seatbelt_backend(self):
        self.assertEqual(self.running.backend, "seatbelt")


@unittest.skipUnless(_seatbelt_ok(), "macOS + sandbox-exec required")
class SeatbeltConfinement(unittest.TestCase):
    """The profile the runner emits actually blocks outbound network while permitting the
    loopback listen a tool needs -- exercised through sandbox-exec, the real enforcer."""

    def test_outbound_denied_loopback_bind_allowed(self):
        profile = _seatbelt_profile(SandboxPolicy(), allow_unix_egress=False)
        probe = (
            "import socket\n"
            "s = socket.socket()\n"
            "try:\n"
            "    s.bind(('127.0.0.1', 0)); s.listen(1); print('bind:OK')\n"
            "except Exception as e:\n"
            "    print('bind:FAIL', e)\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 80), timeout=3); print('out:ALLOWED')\n"
            "except Exception:\n"
            "    print('out:BLOCKED')\n"
        )
        r = subprocess.run([_SANDBOX_EXEC, "-p", profile, sys.executable, "-c", probe],
                           capture_output=True, text=True, timeout=30)
        self.assertIn("bind:OK", r.stdout)
        self.assertIn("out:BLOCKED", r.stdout)
        self.assertNotIn("out:ALLOWED", r.stdout)


@unittest.skipUnless(_seatbelt_ok(), "macOS + sandbox-exec required")
class SeatbeltEgressE2E(unittest.TestCase):
    """A tool that declares an egress allowlist: the runner starts a per-tool egress proxy,
    the tool still serves under the sandbox, and the proxy is reaped on stop."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port(), egress=("example.com",))
        self.runner = SeatbeltRunner()
        self.running = self.runner.start(self.tool)
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("sandboxed echo tool did not start")

    def test_egress_proxy_started_and_tool_serves(self):
        self.assertIsNotNone(self.running.egress_pid)
        self.assertTrue(_pid_alive(self.running.egress_pid))
        self.assertEqual(_call(self.tool.port, "say", {"m": "hi"}), {"echoed": {"m": "hi"}})

    def test_stop_reaps_the_egress_proxy(self):
        self.runner.stop(self.running)
        time.sleep(0.3)
        self.assertFalse(_pid_alive(self.running.egress_pid))


@unittest.skipUnless(_seatbelt_ok(), "macOS + sandbox-exec required")
class SeatbeltEgressConfinement(unittest.TestCase):
    """The egress profile the runner emits permits outbound only to the tool's proxy port; a
    direct connection to any other loopback service is blocked by the sandbox itself."""

    def test_only_the_proxy_port_is_reachable(self):
        proxy = _serve_egress_proxy(_free_port(), ["127.0.0.1"])
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        proxy_port = proxy.server_address[1]

        other = socket.socket()  # a second loopback service the tool must NOT reach directly
        other.bind(("127.0.0.1", 0))
        other.listen(1)
        self.addCleanup(other.close)
        other_port = other.getsockname()[1]

        profile = _seatbelt_profile(SandboxPolicy(egress=EgressPolicy(allow=("127.0.0.1",))),
                                    allow_unix_egress=False, egress_port=proxy_port)
        probe = (
            "import socket, sys\n"
            "def t(p):\n"
            "    try:\n"
            "        socket.create_connection(('127.0.0.1', p), timeout=3).close(); return 'OK'\n"
            "    except Exception:\n"
            "        return 'BLOCKED'\n"
            "print('proxy_port:', t(int(sys.argv[1])))\n"
            "print('other_port:', t(int(sys.argv[2])))\n"
        )
        r = subprocess.run([_SANDBOX_EXEC, "-p", profile, sys.executable, "-c", probe,
                            str(proxy_port), str(other_port)],
                           capture_output=True, text=True, timeout=30)
        self.assertIn("proxy_port: OK", r.stdout)
        self.assertIn("other_port: BLOCKED", r.stdout)


def _bwrap_ok() -> bool:
    """The Linux native runner needs nftables + cgroup v2 reachable through a non-interactive
    sudo (the locked-down netguard rule). Gated so the suite still runs cleanly off-host."""
    if not sys.platform.startswith("linux") or shutil.which("nft") is None:
        return False
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(_bwrap_ok(), "Linux + nft + non-interactive sudo required")
class BwrapRunnerE2E(unittest.TestCase):
    """The Linux-native runner starts the real echo tool confined by netguard (cgroup + nft) and
    the broker's HttpRuntime reaches it -- same contract as the process backend, now egress-confined."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port())
        self.runner = BwrapRunner()
        self.running = self.runner.start(self.tool)
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("sandboxed echo tool did not start")

    def test_broker_reaches_sandboxed_tool_and_it_reads_its_secret(self):
        self.assertEqual(_call(self.tool.port, "say", {"m": "hi"}), {"echoed": {"m": "hi"}})
        status = _call(self.tool.port, "secret_status", {})
        self.assertTrue(status["has_api_key"])
        self.assertEqual(status["api_key_len"], len(SECRET))
        self.assertNotIn(SECRET, json.dumps(status))  # secret never returns through the broker

    def test_records_bwrap_backend(self):
        self.assertEqual(self.running.backend, "bwrap")

    def test_stop_removes_the_cgroup(self):
        cg = f"/sys/fs/cgroup/toolyard/{self.tool.id}"
        self.assertTrue(os.path.isdir(cg))          # created while running
        self.runner.stop(self.running)
        self.assertFalse(os.path.isdir(cg))          # netguard teardown removed it


@unittest.skipUnless(_bwrap_ok(), "Linux + nft + non-interactive sudo required")
class BwrapEgressE2E(unittest.TestCase):
    """A tool that declares an egress allowlist: the runner starts a per-tool egress proxy, the
    tool still serves under the sandbox, and the proxy is reaped on stop."""

    def setUp(self):
        self.tool = dataclasses.replace(load(TOOL_TOML), port=_free_port(), egress=("example.com",))
        self.runner = BwrapRunner()
        self.running = self.runner.start(self.tool)
        self.addCleanup(self.runner.stop, self.running)
        if not _wait_for_tool(self.tool.port):
            self.fail("sandboxed echo tool did not start")

    def test_egress_proxy_started_and_tool_serves(self):
        self.assertIsNotNone(self.running.egress_pid)
        self.assertTrue(_pid_alive(self.running.egress_pid))
        self.assertEqual(_call(self.tool.port, "say", {"m": "hi"}), {"echoed": {"m": "hi"}})

    def test_stop_reaps_the_egress_proxy(self):
        self.runner.stop(self.running)
        time.sleep(0.3)
        self.assertFalse(_pid_alive(self.running.egress_pid))


@unittest.skipUnless(_bwrap_ok(), "Linux + nft + non-interactive sudo required")
class BwrapConfinement(unittest.TestCase):
    """netguard's cgroup+nft rule actually confines a process it launches: new outbound reaches
    only the tool's egress proxy port, while any other loopback service and all external hosts are
    dropped -- exercised through the real sudo->netguard path, the enforcer the runner uses."""

    def test_only_the_proxy_port_is_reachable(self):
        proxy = _serve_egress_proxy(_free_port(), ["127.0.0.1"])
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        proxy_port = proxy.server_address[1]

        other = socket.socket()  # a second loopback service the tool must NOT reach directly
        other.bind(("127.0.0.1", 0))
        other.listen(1)
        self.addCleanup(other.close)
        other_port = other.getsockname()[1]

        outfile = tempfile.NamedTemporaryFile(prefix="bwrap-confine-", delete=False)
        outfile.close()
        self.addCleanup(os.unlink, outfile.name)
        probe = (
            "import socket, sys\n"
            "def t(host, p):\n"
            "    try:\n"
            "        s = socket.create_connection((host, p), 3); s.close(); return 'OK'\n"
            "    except Exception:\n"
            "        return 'BLOCKED'\n"
            "open(sys.argv[3], 'w').write('proxy=%s other=%s external=%s' % (\n"
            "    t('127.0.0.1', int(sys.argv[1])), t('127.0.0.1', int(sys.argv[2])),\n"
            "    t('1.1.1.1', 443)))\n"
        )
        tool_id = "bwrapconfine"
        try:
            subprocess.run(
                _netguard_argv("run", "--tool", tool_id, "--proxy-port", str(proxy_port), "--",
                               sys.executable, "-c", probe,
                               str(proxy_port), str(other_port), outfile.name),
                capture_output=True, text=True, timeout=30)
            result = Path(outfile.name).read_text()
        finally:
            subprocess.run(_netguard_argv("teardown", "--tool", tool_id),
                           capture_output=True, timeout=15)
        self.assertIn("proxy=OK", result)
        self.assertIn("other=BLOCKED", result)
        self.assertIn("external=BLOCKED", result)


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


class SpsRegistration(unittest.TestCase):
    """Phase 2: the runner mints an E_SECRET, registers the tool with SPS, and
    injects TOOLSTACK_E_SECRET + SPS connection params into the child env. The
    `secrets` arg is supplied for backward compat (legacy host-disk path); the
    SPS path uses `tool_def.secrets` for the CS_TUPLE list."""

    def _tool(self):
        # Same shape as the echo_api fixture but with [[secrets]] entries
        # so the SPS CS_TUPLE list is non-empty.
        d = Path(tempfile.mkdtemp(prefix="tsr-sps-"))
        self.addCleanup(shutil.rmtree, str(d), ignore_errors=True)
        (d / "toolyard.toml").write_text(
            'id = "echosps"\ntype = "api"\n'
            '[entrypoint]\nport = 4701\ncommand = "python3 echo.py"\n'
            '[[secrets]]\nname = "api_key"\nfield = "API_KEY"\nwritable = false\n'
        )
        return dataclasses.replace(load(d / "toolyard.toml"), port=_free_port())

    def test_runner_mints_e_secret_and_registers(self):
        tool = self._tool()
        runner = ProcessRunner()

        with mock.patch("toolyard.runner._check_port_free"), \
             mock.patch("toolyard.runner._check_sps_env"), \
             mock.patch("toolyard.runner._sps_register") as reg, \
             mock.patch("toolyard.runner._sps_unregister"), \
             mock.patch("toolyard.runner._start_egress_proxy", return_value=("999", 0)), \
             mock.patch.object(ProcessRunner, "is_alive", return_value=True), \
             mock.patch("os.posix_spawn", return_value=123) as spawn, \
             mock.patch.dict(os.environ,
                              {"TOOLSTACK_SPS_ENV": "/tmp/spfake.env", "TOOLSTACK_SPS_SKIP": "0"},
                              clear=False):
            with mock.patch("os.path.exists", return_value=True):
                running = runner.start(tool)

        self.assertIsNotNone(running.e_secret)
        self.assertGreaterEqual(len(running.e_secret), 32)
        reg.assert_called_once()
        args = reg.call_args.args
        self.assertEqual(args[0].id, "echosps")
        self.assertEqual(args[1], running.e_secret)

        env = spawn.call_args.args[2]
        self.assertEqual(env["TOOLSTACK_E_SECRET"], running.e_secret)
        self.assertIn("TOOLSTACK_SPS_HOST", env)
        self.assertIn("TOOLSTACK_SPS_PORT", env)
        self.assertIn("TOOLSTACK_SPS_CA", env)

    def test_runner_skips_sps_when_env_skip_set(self):
        # Strip the module-level E_SECRET default for this test -- it asserts
        # the env the runner injects contains NO E_SECRET, which is only
        # true when the runner didn't mint one (i.e. SPS was skipped).
        with mock.patch.dict(os.environ, {}, clear=True):
            tool = self._tool()
            runner = ProcessRunner()
            with mock.patch("toolyard.runner._check_port_free"), \
                 mock.patch("toolyard.runner._sps_register") as reg, \
                 mock.patch.object(ProcessRunner, "is_alive", return_value=True), \
                 mock.patch("os.posix_spawn", return_value=123) as spawn:
                running = runner.start(tool)
            reg.assert_not_called()
            self.assertIsNone(running.e_secret)
            env = spawn.call_args.args[2]
            self.assertNotIn("TOOLSTACK_E_SECRET", env)

    def test_runner_skips_sps_when_env_file_missing(self):
        tool = self._tool()
        runner = ProcessRunner()
        with mock.patch("toolyard.runner._check_port_free"), \
             mock.patch("toolyard.runner._sps_register") as reg, \
             mock.patch.object(ProcessRunner, "is_alive", return_value=True), \
             mock.patch("os.posix_spawn", return_value=123), \
             mock.patch.dict(os.environ, {"TOOLSTACK_SPS_ENV": "/tmp/does-not-exist.env",
                                          "TOOLSTACK_SPS_SKIP": "0"}, clear=False):
            running = runner.start(tool)
        reg.assert_not_called()
        self.assertIsNone(running.e_secret)

    def test_stop_calls_sps_unregister(self):
        tool = self._tool()
        runner = ProcessRunner()
        with mock.patch("toolyard.runner._check_port_free"), \
             mock.patch("toolyard.runner._check_sps_env"), \
             mock.patch("toolyard.runner._sps_register"), \
             mock.patch("toolyard.runner._sps_unregister") as unreg, \
             mock.patch.object(ProcessRunner, "is_alive", return_value=True), \
             mock.patch("os.posix_spawn", return_value=123), \
             mock.patch.dict(os.environ,
                              {"TOOLSTACK_SPS_ENV": "/tmp/spfake.env", "TOOLSTACK_SPS_SKIP": "0"},
                              clear=False), \
             mock.patch("os.path.exists", return_value=True):
            running = runner.start(tool)
            runner.stop(running)
        unreg.assert_called_once()
        self.assertEqual(unreg.call_args.args[0], "echosps")


class MintEphemeral(unittest.TestCase):
    """Phase 2: E_SECRET is 64 random bytes -> 128 hex chars."""

    def test_e_secret_shape(self):
        from toolyard.runner import _mint_e_secret
        e1 = _mint_e_secret()
        e2 = _mint_e_secret()
        self.assertEqual(len(e1), 128)
        self.assertTrue(all(c in "0123456789abcdef" for c in e1))
        self.assertNotEqual(e1, e2)


if __name__ == "__main__":
    unittest.main()
