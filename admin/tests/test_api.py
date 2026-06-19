"""admin.api (the JSON operator API) via FastAPI's TestClient: bearer-token auth and the
broker status/control endpoints. No broker process is started (supervisor patched / reports
stopped). Requires the admin venv:  admin/.venv/bin/python -m unittest admin.tests.test_api
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from admin import auth, broker_config, settings, tool_authoring
from admin.broker_config import BrokerRunConfig
from admin.server import create_app
from broker.store import Store

PASSWORD = "hunter2-admin"


class JsonApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-api-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._env = {}
        for key, sub in (("XDG_CONFIG_HOME", "config"), ("XDG_STATE_HOME", "state")):
            self._env[key] = os.environ.get(key)
            os.environ[key] = str(Path(self.tmp, sub))
        self.addCleanup(self._restore_env)

        settings.write_password_hash(auth.hash_password(PASSWORD))
        tool_dir = Path(self.tmp, "tools", "echo")
        tool_dir.mkdir(parents=True)
        (tool_dir / "toolyard.toml").write_text(
            'id = "echo"\ntype = "rest"\ndescription = "echo tool"\n\n'
            '[entrypoint]\ncommand = "python3 app.py"\nport = 4601\n\n'
            '[[operations]]\nname = "say"\nrisk = "low"\ndescription = "echo a message"\n\n'
            '[[secrets]]\nname = "api_key"\nfield = "API_KEY"\nwritable = true\n',
            encoding="utf-8")
        self.db_path = str(Path(self.tmp, "broker.sqlite3"))
        broker_config.save(BrokerRunConfig(db_path=self.db_path, tools_root=str(Path(self.tmp, "tools"))))
        self.client = TestClient(create_app())

    def _restore_env(self):
        for key, prev in self._env.items():
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev

    def _token(self) -> str:
        r = self.client.post("/api/login", json={"password": PASSWORD})
        self.assertEqual(r.status_code, 200)
        return r.json()["token"]

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}"}

    # --- auth -----------------------------------------------------------------
    def test_login_issues_a_token(self):
        r = self.client.post("/api/login", json={"password": PASSWORD})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["token"])
        self.assertEqual(body["username"], "admin")
        # the token is a valid session for the same secret the cookie uses
        self.assertEqual(auth.verify_session(body["token"],
                                             settings.load_or_create_session_secret()), "admin")

    def test_login_bad_password_401(self):
        r = self.client.post("/api/login", json={"password": "wrong"})
        self.assertEqual(r.status_code, 401)

    def test_login_requires_json_object(self):
        r = self.client.post("/api/login", content=b"not json")
        self.assertEqual(r.status_code, 400)

    def test_protected_route_needs_a_token(self):
        self.assertEqual(self.client.get("/api/broker").status_code, 401)
        self.assertEqual(self.client.get("/api/broker",
                                         headers={"Authorization": "Bearer nope"}).status_code, 401)

    # --- broker status / control ---------------------------------------------
    def test_broker_status_when_stopped(self):
        r = self.client.get("/api/broker", headers=self._auth())
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["running"])  # no broker started in tests

    def test_unknown_broker_action_400(self):
        r = self.client.post("/api/broker/bogus", headers=self._auth())
        self.assertEqual(r.status_code, 400)

    def test_broker_start_calls_supervisor_and_audits(self):
        # patch the supervisor so no real broker is spawned; assert the route wires through
        # to it AND records the same admin.broker_started audit event the HTML handler does.
        with mock.patch("admin.supervisor.start") as start, \
             mock.patch("admin.supervisor.status", return_value={"running": True, "pid": 1,
                                                                 "port": 8765, "healthy": True}):
            r = self.client.post("/api/broker/start", headers=self._auth())
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["running"])
        start.assert_called_once()
        store = Store(self.db_path)
        self.addCleanup(store.close)
        pairs = [(e["component"], e["event_type"]) for e in store.audit_events()]
        self.assertIn(("admin", "broker_started"), pairs)

    def test_broker_start_failure_is_502(self):
        with mock.patch("admin.supervisor.start", side_effect=RuntimeError("boom")):
            r = self.client.post("/api/broker/start", headers=self._auth())
        self.assertEqual(r.status_code, 502)

    # --- callers / policy / tokens -------------------------------------------
    def _create(self, name="hermes", **body):
        return self.client.post("/api/callers", headers=self._auth(), json={"name": name, **body})

    def test_create_and_list_callers(self):
        r = self._create("hermes", allow=["echo.say"])
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["token"])  # token shown once
        listing = self.client.get("/api/callers", headers=self._auth()).json()
        self.assertIn("hermes", [c["name"] for c in listing["callers"]])
        self.assertTrue(listing["tokens"])  # the initial token is listed (hashed)

    def test_create_duplicate_is_409(self):
        self._create("hermes")
        self.assertEqual(self._create("hermes").status_code, 409)

    def test_create_requires_name(self):
        self.assertEqual(self.client.post("/api/callers", headers=self._auth(), json={}).status_code, 400)

    def test_create_rejects_bad_allow_type(self):
        r = self.client.post("/api/callers", headers=self._auth(),
                             json={"name": "x", "allow": "echo.say"})  # str, not list
        self.assertEqual(r.status_code, 400)

    def test_revoke_caller_and_missing_404(self):
        self._create("hermes")
        self.assertEqual(self.client.post("/api/callers/hermes/revoke", headers=self._auth()).status_code, 200)
        self.assertEqual(self.client.post("/api/callers/ghost/revoke", headers=self._auth()).status_code, 404)

    def test_rotate_token_returns_new(self):
        first = self._create("hermes").json()["token"]
        rotated = self.client.post("/api/callers/hermes/rotate-token", headers=self._auth())
        self.assertEqual(rotated.status_code, 200)
        self.assertTrue(rotated.json()["token"])
        self.assertNotEqual(rotated.json()["token"], first)

    def test_revoke_token_empty_prefix_400(self):
        r = self.client.post("/api/tokens/revoke", headers=self._auth(), json={"prefix": "  "})
        self.assertEqual(r.status_code, 400)

    def test_policy_round_trip(self):
        self._create("hermes", allow=["echo.say"])
        got = self.client.get("/api/callers/hermes/policy", headers=self._auth()).json()
        self.assertEqual(got["policy"]["tools"]["echo"]["say"], "allow")
        put = self.client.put("/api/callers/hermes/policy", headers=self._auth(),
                              json={"review": ["echo.shout"]})
        self.assertEqual(put.status_code, 200)
        self.assertEqual(put.json()["policy"]["tools"]["echo"]["shout"], "review")

    def test_policy_missing_caller_404(self):
        self.assertEqual(self.client.get("/api/callers/ghost/policy", headers=self._auth()).status_code, 404)

    def test_set_enabled_tools(self):
        self._create("hermes")
        r = self.client.put("/api/callers/hermes/tools", headers=self._auth(),
                            json={"enabled": ["echo"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["enabled"], ["echo"])

    # --- observe / discover ---------------------------------------------------
    def test_audit_returns_events(self):
        self._create("hermes")  # records an admin.caller_created event
        body = self.client.get("/api/audit", headers=self._auth()).json()
        pairs = [(e["component"], e["event_type"]) for e in body["audit"]]
        self.assertIn(("admin", "caller_created"), pairs)
        self.assertIn("requests", body)

    def test_tools_config_secret_backend(self):
        tools = self.client.get("/api/tools", headers=self._auth())
        self.assertEqual(tools.status_code, 200)
        echo = next(t for t in tools.json()["tools"] if t["id"] == "echo")
        self.assertEqual([op["op"] for op in echo["ops"]], ["say"])  # ops attached for the policy editor
        self.assertEqual(echo["description"], "echo tool")
        self.assertEqual(echo["secrets"], [{"name": "api_key", "field": "API_KEY",
                                            "writable": True, "vault": None, "item": None}])
        cfg = self.client.get("/api/config", headers=self._auth())
        self.assertEqual(cfg.status_code, 200)
        self.assertIn("port", cfg.json())
        sb = self.client.get("/api/secret-backend", headers=self._auth()).json()
        self.assertIn("name", sb)

    def test_edit_tool_updates_description_and_secrets(self):
        r = self.client.post("/api/tools/echo", headers=self._auth(), json={
            "description": "now with feeling",
            "secrets": [{"name": "api_key", "field": "NEW_KEY", "writable": False},
                        {"name": "token", "field": "TOKEN", "writable": True, "vault": "Proj"}]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["description"], "now with feeling")
        # the change is persisted: GET reflects the new description + secrets, ops untouched
        echo = next(t for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]
                    if t["id"] == "echo")
        self.assertEqual(echo["description"], "now with feeling")
        self.assertEqual({s["field"] for s in echo["secrets"]}, {"NEW_KEY", "TOKEN"})
        self.assertEqual([op["op"] for op in echo["ops"]], ["say"])  # operations preserved

    def test_edit_tool_description_only_keeps_secrets(self):
        # Omitting "secrets" leaves the existing declarations in place.
        self.client.post("/api/tools/echo", headers=self._auth(), json={"description": "just a note"})
        echo = next(t for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]
                    if t["id"] == "echo")
        self.assertEqual(echo["description"], "just a note")
        self.assertEqual([s["name"] for s in echo["secrets"]], ["api_key"])

    def test_edit_tool_ignores_entrypoint_and_ops_in_body(self):
        # Security-critical: the endpoint edits ONLY description + secrets. command/image/port/
        # operations come from disk and must NOT be overridable via the request body — otherwise a
        # caller could repoint a tool at arbitrary code.
        r = self.client.post("/api/tools/echo", headers=self._auth(), json={
            "description": "x", "command": "rm -rf /", "image": "evil:latest",
            "port": 9999, "operations": [{"name": "pwn", "risk": "low"}]})
        self.assertEqual(r.status_code, 200, r.text)
        on_disk = tool_authoring.read(Path(self.tmp, "tools", "echo"))
        self.assertEqual(on_disk["command"], "python3 app.py")  # unchanged
        self.assertEqual(on_disk["image"], "")                  # not injected
        self.assertEqual(on_disk["port"], 4601)                 # unchanged
        self.assertEqual([o["name"] for o in on_disk["operations"]], ["say"])  # unchanged

    def test_edit_tool_unknown_404(self):
        r = self.client.post("/api/tools/ghost", headers=self._auth(), json={"description": "x"})
        self.assertEqual(r.status_code, 404)

    def test_edit_tool_invalid_secret_400(self):
        r = self.client.post("/api/tools/echo", headers=self._auth(),
                             json={"secrets": [{"name": "bad name", "field": "X"}]})
        self.assertEqual(r.status_code, 400)

    def test_edit_tool_needs_auth(self):
        self.assertEqual(self.client.post("/api/tools/echo", json={"description": "x"}).status_code, 401)

    def _tool_folder(self, name: str, tool_id: str, port: int = 4700) -> Path:
        src = Path(self.tmp, name)
        src.mkdir()
        (src / "toolyard.toml").write_text(
            f'id = "{tool_id}"\ntype = "rest"\ndescription = "wx"\n\n'
            f'[entrypoint]\ncommand = "python3 app.py"\nport = {port}\n\n'
            '[[operations]]\nname = "today"\nrisk = "low"\n', encoding="utf-8")
        (src / "app.py").write_text("# code\n", encoding="utf-8")
        return src

    def test_add_tool_from_folder(self):
        src = self._tool_folder("src_weather", "weather")
        r = self.client.post("/api/tools", headers=self._auth(), json={"source": str(src)})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["id"], "weather")
        # copied into tools_root, so it now appears in the listing (no broker restart needed to list)
        ids = [t["id"] for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]]
        self.assertIn("weather", ids)

    def test_add_tool_no_manifest_422(self):
        src = Path(self.tmp, "codeonly")
        src.mkdir()
        (src / "app.py").write_text("x", encoding="utf-8")
        r = self.client.post("/api/tools", headers=self._auth(), json={"source": str(src)})
        self.assertEqual(r.status_code, 422)

    def test_add_tool_duplicate_id_400(self):
        src = self._tool_folder("src_echo", "echo", port=4602)  # "echo" already exists from setUp
        r = self.client.post("/api/tools", headers=self._auth(), json={"source": str(src)})
        self.assertEqual(r.status_code, 400)

    def test_add_tool_requires_source(self):
        self.assertEqual(self.client.post("/api/tools", headers=self._auth(), json={}).status_code, 400)

    def test_add_tool_needs_auth(self):
        self.assertEqual(self.client.post("/api/tools", json={"source": "/x"}).status_code, 401)

    def test_config_round_trip_write_only_token_and_validation(self):
        # save settings, partial-merge style
        r = self.client.post("/api/config", headers=self._auth(),
                             json={"approval_ttl": 7200, "rate_limit": 0,
                                   "nod_url": "https://nod.example/boop", "nod_channel": "ops"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["approval_ttl"], 7200)
        self.assertEqual(r.json()["nod_url"], "https://nod.example/boop")
        # nod token is write-only: set it, GET shows "set", and a later save without it KEEPS it
        self.client.post("/api/config", headers=self._auth(), json={"nod_token": "secret-tok-XYZ"})
        self.assertEqual(self.client.get("/api/config", headers=self._auth()).json()["nod_token"], "set")
        self.client.post("/api/config", headers=self._auth(), json={"rate_limit": 5})  # no token
        self.assertEqual(self.client.get("/api/config", headers=self._auth()).json()["nod_token"], "set")
        self.assertNotIn("secret-tok-XYZ", self.client.get("/api/config", headers=self._auth()).text)  # never leaked
        # validation
        self.assertEqual(self.client.post("/api/config", headers=self._auth(), json={"port": 0}).status_code, 400)
        self.assertEqual(self.client.post("/api/config", headers=self._auth(), json={"port": "x"}).status_code, 400)

    def test_operator_routes_need_auth(self):
        for method, path in [("get", "/api/callers"), ("post", "/api/callers"),
                             ("get", "/api/audit"), ("get", "/api/config")]:
            self.assertEqual(getattr(self.client, method)(path).status_code, 401, path)


if __name__ == "__main__":
    unittest.main()
