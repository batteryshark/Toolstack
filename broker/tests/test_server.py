"""Integration: start the real server on an ephemeral port and exercise it
end to end over HTTP, including a real allowed action."""

import json
import threading
import unittest
import urllib.error
import urllib.request

from broker.identity import hash_token
from broker.server import build_server

from .support import FakeRuntime, make_registry


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


if __name__ == "__main__":
    unittest.main()
