"""Integration: start the real server on an ephemeral port and exercise it
end to end over HTTP, including a real allowed action."""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from broker.identity import hash_token
from broker.server import _clear_pidfile, _configured_host, _pidfile_path, _write_pidfile, build_server

from .support import FakeRuntime, make_registry


class BindHost(unittest.TestCase):
    """The bind host is loopback by default; TOOLSTACK_BROKER_HOST overrides it (only the
    in-container case should), so the broker can bind 0.0.0.0 behind a 127.0.0.1 publish."""

    def test_defaults_to_loopback(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TOOLSTACK_BROKER_HOST", None)
            self.assertEqual(_configured_host(), "127.0.0.1")

    def test_nonloopback_fails_closed(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_BROKER_HOST": "0.0.0.0"}):
            os.environ.pop("TOOLSTACK_BROKER_ALLOW_NONLOOPBACK", None)
            with self.assertRaises(SystemExit):  # exposes the broker; refuse without the opt-in
                _configured_host()

    def test_nonloopback_allowed_with_optin(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_BROKER_HOST": "0.0.0.0",
                                          "TOOLSTACK_BROKER_ALLOW_NONLOOPBACK": "1"}):
            self.assertEqual(_configured_host(), "0.0.0.0")

    def test_build_server_honors_explicit_host(self):
        server = build_server(port=0, host="127.0.0.1", db_path=":memory:", audit_sink=None,
                              registry=make_registry({"echo": {"say": "low"}}), runtime=FakeRuntime())
        self.addCleanup(server.server_close)
        self.addCleanup(server.ctx.store.close)
        self.assertEqual(server.server_address[0], "127.0.0.1")


class ServerIntegration(unittest.TestCase):
    def setUp(self):
        self.server = build_server(
            port=0,
            db_path=":memory:",
            audit_sink=None,
            registry=make_registry({"echo": {"say": "low", "secret": "high"}}),
            runtime=FakeRuntime(),
        )
        self.host, self.port = self.server.server_address

        store = self.server.ctx.store
        caller_id = store.add_caller("hermes")
        self.token = "itest-token"
        store.add_token(caller_id, hash_token(self.token))
        store.set_policy(caller_id, {"tools": {"echo": {"say": "allow"}}})

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.server.ctx.store.close()

    def _req(self, method, path, headers=None, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data,
            headers=headers or {}, method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read()), dict(resp.headers)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read()), dict(e.headers)
            finally:
                e.close()

    def _auth(self):
        return {"Authorization": f"Bearer {self.token}"}

    def test_bound_to_localhost_only(self):
        self.assertEqual(self.host, "127.0.0.1")

    def test_health_ok(self):
        status, body, headers = self._req("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})
        self.assertIn("X-Correlation-Id", headers)

    def test_server_header_does_not_leak_version(self):
        _, _, headers = self._req("GET", "/v1/health")
        self.assertNotIn("Python", headers.get("Server", ""))

    def test_unauthenticated_action_401(self):
        status, _, _ = self._req("POST", "/v1/actions/echo.say", body={"arguments": {}})
        self.assertEqual(status, 401)

    def test_allowed_action_runs_over_http(self):
        status, body, _ = self._req(
            "POST", "/v1/actions/echo.say", headers=self._auth(),
            body={"arguments": {"m": "hi"}},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["result"], {"echoed": {"m": "hi"}})

    def test_denied_action_403(self):
        status, _, _ = self._req(
            "POST", "/v1/actions/echo.secret", headers=self._auth(), body={"arguments": {}}
        )
        self.assertEqual(status, 403)

    def test_unknown_tool_404(self):
        status, _, _ = self._req(
            "POST", "/v1/actions/echo.ghost", headers=self._auth(), body={"arguments": {}}
        )
        self.assertEqual(status, 404)

    def test_declared_oversize_action_body_returns_413(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_REST_BODY_MAX": "1"}):
            status, body, _ = self._req(
                "POST", "/v1/actions/echo.say", headers=self._auth(),
                body={"arguments": {"body": "x" * (70 * 1024)}},
            )
        self.assertEqual(status, 413)
        self.assertEqual(body["error"], "body_too_large")

    # --- broker-native MCP framing over HTTP (T-021) ------------------------

    def test_mcp_unauthenticated_401(self):
        status, _, _ = self._req("POST", "/mcp",
                                 body={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(status, 401)

    def test_mcp_initialize_over_http(self):
        status, body, _ = self._req(
            "POST", "/mcp", headers=self._auth(),
            body={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "toolstack-broker")

    def test_mcp_tools_call_allow_over_http(self):
        # MCP frame over the wire -> real gateway/lifecycle -> runtime -> MCP result back.
        status, body, _ = self._req(
            "POST", "/mcp", headers=self._auth(),
            body={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "echo__say", "arguments": {"m": "hi"}}})
        self.assertEqual(status, 200)
        result = body["result"]
        self.assertFalse(result["isError"])
        inner = json.loads(result["content"][0]["text"])
        self.assertEqual(inner["result"], {"echoed": {"m": "hi"}})

    # --- audit taxonomy (T-018/T-019) ---------------------------------------

    def _audit_pairs(self, **filt):
        return [(e["component"], e["event_type"])
                for e in self.server.ctx.store.audit_events(**filt)]

    def test_identity_events_on_auth_success_and_failure(self):
        self._req("GET", "/v1/tools", headers=self._auth())                 # valid token
        self._req("GET", "/v1/tools", headers={"Authorization": "Bearer nope"})  # bad token
        pairs = self._audit_pairs()
        self.assertIn(("identity", "token_validated"), pairs)
        self.assertIn(("identity", "token_rejected"), pairs)

    def test_request_completed_event_on_allowed_action(self):
        _, body, _ = self._req("POST", "/v1/actions/echo.say",
                               headers=self._auth(), body={"arguments": {}})
        req_events = [et for c, et in self._audit_pairs(request_id=body["request_id"])
                      if c == "request"]
        self.assertIn("received", req_events)
        self.assertIn("completed", req_events)  # the terminal outcome event

    def test_request_denied_event_on_denied_action(self):
        _, body, _ = self._req("POST", "/v1/actions/echo.secret",  # not in policy -> deny
                               headers=self._auth(), body={"arguments": {}})
        req_events = [et for c, et in self._audit_pairs(request_id=body["request_id"])
                      if c == "request"]
        self.assertIn("denied", req_events)


class NodSurfaceFromEnv(unittest.TestCase):
    """When TOOLSTACK_NOD_URL/TOKEN are set, build_server wires a NodSurface from
    the environment. The channel must be configurable; a token scoped to one nod
    channel 403s on another, so the broker has to be able to target the right one."""

    _NOD_KEYS = ("TOOLSTACK_NOD_URL", "TOOLSTACK_NOD_TOKEN", "TOOLSTACK_NOD_CHANNEL")

    def _build(self, env):
        # Isolate from the real environment: snapshot (restored on exit), clear
        # all nod keys, then apply exactly what this case sets.
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in self._NOD_KEYS:
                os.environ.pop(k, None)
            os.environ.update(env)
            server = build_server(
                port=0, db_path=":memory:", audit_sink=None,
                registry=make_registry({"echo": {"say": "low"}}),
                runtime=FakeRuntime(),
            )
        self.addCleanup(server.server_close)
        self.addCleanup(server.ctx.store.close)
        return server

    def test_channel_from_env(self):
        server = self._build({
            "TOOLSTACK_NOD_URL": "https://nod.example/boop",
            "TOOLSTACK_NOD_TOKEN": "tok",
            "TOOLSTACK_NOD_CHANNEL": "toolserver",
        })
        self.assertIsNotNone(server.ctx.surface)
        self.assertEqual(server.ctx.surface._channel, "toolserver")

    def test_channel_defaults_to_default_when_unset(self):
        server = self._build({
            "TOOLSTACK_NOD_URL": "https://nod.example/boop",
            "TOOLSTACK_NOD_TOKEN": "tok",
        })
        self.assertEqual(server.ctx.surface._channel, "default")

    def test_no_surface_without_nod_env(self):
        server = self._build({})
        self.assertIsNone(server.ctx.surface)


class RegistryReload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = Path(self.tmp, "tools")
        self.root.mkdir()
        self.tool = self.root / "echo"
        self.tool.mkdir()
        self._write("echo", 4600, "say")
        self.server = build_server(
            port=0, host="127.0.0.1", db_path=":memory:", audit_sink=None,
            tools_root=str(self.root), runtime=FakeRuntime(),
        )
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.ctx.store.close)

    def _write(self, tool_id, port, op):
        d = self.root / tool_id
        d.mkdir(exist_ok=True)
        (d / "toolyard.toml").write_text(
            f'id = "{tool_id}"\ntype = "api"\n[entrypoint]\nport = {port}\n'
            f'[[operations]]\nname = "{op}"\nrisk = "read"\n'
        )

    def test_reload_adds_new_tool(self):
        self._write("weather", 4700, "today")
        self.server.reload_registry()
        self.assertIsNotNone(self.server.ctx.registry.lookup("weather", "today"))

    def test_reload_removes_deleted_tool(self):
        shutil.rmtree(self.tool)
        self.server.reload_registry()
        self.assertIsNone(self.server.ctx.registry.lookup("echo", "say"))

    def test_reload_uses_new_port(self):
        self._write("echo", 4701, "say")
        self.server.reload_registry()
        self.assertEqual(self.server.ctx.registry.lookup("echo", "say").port, 4701)

    def test_reload_audits_before_after_counts(self):
        self._write("weather", 4700, "today")
        self.server.reload_registry()
        event = self.server.ctx.store.recent_audit(limit=1)[0]
        self.assertEqual(event["component"], "registry")
        self.assertEqual(event["event_type"], "reloaded")
        self.assertEqual(event["details"]["tools_before"], 1)
        self.assertEqual(event["details"]["tools_after"], 2)


class Pidfile(unittest.TestCase):
    def test_write_and_clear_pidfile_under_xdg_state_home(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": tmp}):
            _write_pidfile()
            path = _pidfile_path()
            self.assertEqual(path.read_text(), str(os.getpid()))
            _clear_pidfile()
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
