"""admin.api (the JSON operator API) via FastAPI's TestClient: bearer-token auth and the
broker status/control endpoints. No broker process is started (supervisor patched / reports
stopped). Requires the admin venv:  admin/.venv/bin/python -m unittest admin.tests.test_api
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import closing
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
        # a clean secret-backend env so secret_backend() deterministically defaults to 'file'
        for key in ("TOOLSTACK_SECRET_BACKEND", "TOOLSTACK_VAULT_FILE", "TOOLSTACK_VAULT_PASSPHRASE"):
            self._env[key] = os.environ.get(key)
            os.environ.pop(key, None)
        self.addCleanup(self._restore_env)

        settings.write_password_hash(auth.hash_password(PASSWORD))
        tool_dir = Path(self.tmp, "tools", "echo")
        tool_dir.mkdir(parents=True)
        (tool_dir / "toolyard.toml").write_text(
            'id = "echo"\ntype = "api"\ndescription = "echo tool"\n\n'
            '[entrypoint]\ncommand = "python3 app.py"\nport = 4601\n\n'
            '[[operations]]\nname = "say"\nrisk = "read"\ndescription = "echo a message"\n\n'
            '[[secrets]]\nname = "api_key"\nfield = "API_KEY"\nwritable = true\n',
            encoding="utf-8")
        self.db_path = str(Path(self.tmp, "broker.sqlite3"))
        broker_config.save(BrokerRunConfig(db_path=self.db_path, tools_root=str(Path(self.tmp, "tools"))))
        self.client = TestClient(create_app(), base_url="http://127.0.0.1")

    def _restore_env(self):
        for key, prev in self._env.items():
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev

    def test_logout_revokes_only_presented_session_and_survives_app_recreation(self):
        first, second = self._auth(), self._auth()
        self.assertNotEqual(first, second)
        self.assertEqual(self.client.post("/api/logout", headers=first).status_code, 200)
        fresh = TestClient(create_app(), base_url="http://127.0.0.1")
        self.assertEqual(fresh.get("/api/config", headers=first).status_code, 401)
        self.assertEqual(fresh.get("/api/config", headers=second).status_code, 200)
        self.assertEqual((settings.config_dir() / "revoked-sessions.json").stat().st_mode & 0o777, 0o600)

    def test_host_is_checked_before_login(self):
        for host in ("attacker.invalid", "localhost.attacker.invalid", "127.0.0.1.attacker.invalid"):
            self.assertEqual(self.client.post("/api/login", headers={"Host": host}, json={"password": PASSWORD}).status_code, 400)
        for host in ("localhost:8780", "127.0.0.1:8780", "[::1]:8780"):
            self.assertEqual(self.client.post("/api/login", headers={"Host": host}, json={"password": PASSWORD}).status_code, 200)
        with mock.patch.dict(os.environ, {"TOOLSTACK_ADMIN_HOST": "configured.invalid", "TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK": "1"}):
            self.assertEqual(self.client.post("/api/login", headers={"Host": "configured.invalid"}, json={"password": PASSWORD}).status_code, 200)

    def test_audit_requests_have_only_metadata(self):
        from broker.tests.support import seed_caller, make_registry, FakeRuntime
        from broker.context import BrokerContext
        from broker.audit import AuditLog
        from broker.identity import authenticate
        from broker.request_lifecycle import submit
        with closing(Store(self.db_path)) as store:
            token = seed_caller(store, allow=["echo.say"])
            ctx = BrokerContext(store=store, registry=make_registry({"echo": {"say": "read"}}), runtime=FakeRuntime(), audit=AuditLog(store, sink=None))
            submit(ctx, authenticate(store, f"Bearer {token}"), "echo", "say", {"private": "fake-payload"}, "fake-correlation")
        response = self.client.get("/api/audit", headers=self._auth())
        self.assertEqual(response.status_code, 200)
        row = response.json()["requests"][0]
        self.assertEqual(row["correlation_id"], "fake-correlation")
        self.assertEqual(row["status"], "completed")
        self.assertFalse({"arguments_json", "action_json", "result_json"} & row.keys())
        self.assertNotIn("fake-payload", response.text)

    def test_reset_invalidates_live_bearer_without_restart(self):
        authz = self._auth()
        self.assertEqual(self.client.get("/api/config", headers=authz).status_code, 200)
        settings.write_password_hash(auth.hash_password("replacement-fake"))
        settings.rotate_session_secret()
        self.assertEqual(self.client.get("/api/config", headers=authz).status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"password": PASSWORD}).status_code, 401)
        token = self.client.post("/api/login", json={"password": "replacement-fake"}).json()["token"]
        self.assertEqual(self.client.get("/api/config", headers={"Authorization": f"Bearer {token}"}).status_code, 200)

    def test_external_delete_unregisters_only_matching_source(self):
        folder = Path(self.tmp, 'external')
        folder.mkdir()
        manifest = folder / 'toolyard.toml'
        content = 'id="external"\ntype="api"\n[entrypoint]\nport=43211\n'
        manifest.write_text(content)
        config = broker_config.load()
        config.tool_dirs = [str(folder), str(Path(self.tmp, 'other'))]
        broker_config.save(config)
        self.assertEqual(self.client.delete('/api/tools/external').status_code, 401)
        with mock.patch('admin.tool_removal.toolyard_ops.stop') as stop:
            response = self.client.delete('/api/tools/external', headers=self._auth())
        self.assertEqual(response.json(), {'removed': 'external', 'deleted': False})
        self.assertEqual(manifest.read_text(), content)
        self.assertEqual(broker_config.load().tool_dirs, [str(Path(self.tmp, 'other'))])
        stop.assert_called_once_with('external')

    def test_catalog_requires_admin_and_legacy_observation_is_unknown(self):
        self.assertEqual(self.client.get('/api/catalog').status_code, 401)
        with mock.patch('admin.catalog_observation.urllib.request.urlopen', side_effect=OSError):
            self.assertEqual(self.client.get('/api/catalog', headers=self._auth()).json(), {'status': 'unknown'})

    def test_catalog_api_membership_is_same_verified_snapshot_after_delete(self):
        import threading
        import urllib.request
        from broker.server import build_server
        config = broker_config.load()
        server = build_server(port=0, host='127.0.0.1', db_path=config.db_path,
                              tools_root=config.tools_root, surface=mock.Mock())
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            config.port = server.server_address[1]
            broker_config.save(config)
            self.assertEqual(self.client.get('/api/catalog').status_code, 401)
            headers = self._auth()
            cached = self.client.get('/api/tools', headers=headers).json()['tools']
            self.assertEqual([t['id'] for t in cached], ['echo'])
            self.assertEqual(self.client.get('/api/catalog', headers=headers).json()['tool_ids'], ['echo'])
            Path(config.tools_root, 'echo', 'toolyard.toml').unlink()
            server.reload_registry()
            receipt = self.client.get('/api/catalog', headers=headers).json()
            self.assertEqual(receipt['status'], 'verified')
            self.assertEqual(receipt['tool_ids'], [])
            with urllib.request.urlopen(f'http://127.0.0.1:{config.port}/v1/health', timeout=2) as response:
                public = json.load(response)
            self.assertEqual(set(public), {'status', 'catalog_observation_id'})
            self.assertEqual(public['catalog_observation_id'], receipt['observation_id'])
        finally:
            server.shutdown()
            thread.join(3)
            server.server_close()
            server.ctx.store.close()

    def test_native_backend_and_unknown_contract_fixture(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/native_api.json").read_text())
        authz = self._auth()
        with mock.patch("admin.settings.sps_info", return_value=fixture["backend"]):
            self.assertEqual(self.client.get("/api/secret-backend", headers=authz).json(), fixture["backend"])
            self.assertEqual(self.client.get("/api/tools/echo/secrets", headers=authz).json(), fixture["secret_status"])

    def test_config_audit_contains_field_names_not_values(self):
        authz = self._auth()
        response = self.client.post("/api/config", headers=authz, json={"nod_token": "fake-sensitive-token", "port": 9999})
        self.assertEqual(response.status_code, 200)
        events = self.client.get("/api/audit", headers=authz).json()["audit"]
        changed = next(e for e in events if e["event_type"] == "config_changed")
        self.assertEqual(set(changed["details"]["fields"]), {"nod_token", "port"})
        self.assertNotIn("fake-sensitive-token", json.dumps(events))

    def test_missing_session_generation_fails_closed(self):
        authz = self._auth()
        settings.session_secret_file().unlink()
        self.assertEqual(self.client.get("/api/config", headers=authz).status_code, 503)

    def test_obsolete_native_provisioning_has_no_success_path(self):
        response = self.client.post("/api/tools/echo/secrets", headers=self._auth(),
                                    json={"field": "API_KEY", "value": "fake-only"})
        self.assertEqual(response.status_code, 410)
        self.assertNotIn("fake-only", response.text)

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

    def test_clear_audit_removes_events(self):
        authz = self._auth()
        self._create("hermes")
        self.assertTrue(self.client.get("/api/audit", headers=authz).json()["audit"])
        r = self.client.delete("/api/audit", headers=authz)
        self.assertEqual(r.status_code, 200)
        audit = self.client.get("/api/audit", headers=authz).json()["audit"]
        self.assertEqual(len(audit), 1)  # deletion itself remains attributable
        self.assertEqual(audit[0]["event_type"], "audit_cleared")

    def test_edit_tool_updates_description_and_secrets(self):
        r = self.client.post("/api/tools/echo", headers=self._auth(), json={
            "description": "now with feeling",
            "confirm_secret_items": True,
            "secrets": [{"name": "api_key", "field": "NEW_KEY", "writable": False},
                        {"name": "token", "field": "TOKEN", "writable": True, "item": "oauth"}]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["description"], "now with feeling")
        # the change is persisted: GET reflects the new description + secrets, ops untouched
        echo = next(t for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]
                    if t["id"] == "echo")
        self.assertEqual(echo["description"], "now with feeling")
        self.assertEqual({s["field"] for s in echo["secrets"]}, {"NEW_KEY", "TOKEN"})
        self.assertEqual([op["op"] for op in echo["ops"]],
                         ["say", "refresh", "refresh_one"])  # declared + generated operations

    def test_edit_tool_description_only_keeps_secrets(self):
        # Omitting "secrets" leaves the existing declarations in place.
        self.client.post("/api/tools/echo", headers=self._auth(), json={"description": "just a note"})
        echo = next(t for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]
                    if t["id"] == "echo")
        self.assertEqual(echo["description"], "just a note")
        self.assertEqual([s["name"] for s in echo["secrets"]], ["api_key"])

    def test_edit_tool_ignores_entrypoint_and_ops_in_body(self):
        # Security-critical: the endpoint edits ONLY description + secrets. command/image/port/
        # operations come from disk and must NOT be overridable via the request body; otherwise a
        # caller could repoint a tool at arbitrary code.
        r = self.client.post("/api/tools/echo", headers=self._auth(), json={
            "description": "x", "command": "rm -rf /", "image": "evil:latest",
            "port": 9999, "operations": [{"name": "pwn", "risk": "read"}]})
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
            f'id = "{tool_id}"\ntype = "api"\ndescription = "wx"\n\n'
            f'[entrypoint]\ncommand = "python3 app.py"\nport = {port}\n\n'
            '[[operations]]\nname = "today"\nrisk = "read"\n', encoding="utf-8")
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

    def test_add_tool_requires_source_or_repo(self):
        self.assertEqual(self.client.post("/api/tools", headers=self._auth(), json={}).status_code, 400)

    def test_add_tool_needs_auth(self):
        self.assertEqual(self.client.post("/api/tools", json={"source": "/x"}).status_code, 401)

    def test_parse_openapi_accepts_object_spec(self):
        spec = {"openapi": "3.0.0",
                "servers": [{"url": "https://api.example.com/v1"}],
                "paths": {"/items/{id}": {"get": {"operationId": "getItem",
                          "parameters": [{"name": "id", "in": "path", "required": True}]}}}}
        r = self.client.post("/api/tools/parse-openapi", headers=self._auth(), json={"spec": spec})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["base_url"], "https://api.example.com/v1")
        self.assertEqual(body["operations"][0]["name"], "getItem")
        self.assertEqual(body["operations"][0]["args"][0]["name"], "variables")

    def test_parse_openapi_rejects_bad_spec(self):
        r = self.client.post("/api/tools/parse-openapi", headers=self._auth(), json={"spec": "{not valid"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("not valid", r.json()["detail"].lower())

    def test_add_tool_from_github(self):
        def fake_clone(cmd, *a, **k):
            dest = Path(cmd[-1])           # `git clone ... -- <url> <dest>`
            dest.mkdir(parents=True)
            (dest / "toolyard.toml").write_text(
                'id = "gh_tool"\ntype = "api"\n[entrypoint]\ncommand = "python3 app.py"\nport = 4900\n\n'
                '[[operations]]\nname = "go"\nrisk = "read"\n', encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch("admin.tool_sources.shutil.which", return_value="/usr/bin/git"), \
             mock.patch("admin.tool_sources.subprocess.run", side_effect=fake_clone):
            r = self.client.post("/api/tools", headers=self._auth(),
                                 json={"repo": "https://github.com/x/y", "ref": "main"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["id"], "gh_tool")
        ids = [t["id"] for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]]
        self.assertIn("gh_tool", ids)

    def test_add_tool_bad_repo_url_400(self):
        r = self.client.post("/api/tools", headers=self._auth(), json={"repo": "file:///etc/passwd"})
        self.assertEqual(r.status_code, 400)

    def test_add_tool_with_manifest_authors_code_only_folder(self):
        code = Path(self.tmp, "code_only")
        code.mkdir()
        (code / "app.py").write_text("# code, no manifest\n", encoding="utf-8")
        r = self.client.post("/api/tools", headers=self._auth(), json={
            "source": str(code),
            "manifest": {"id": "authored", "type": "api", "command": "python3 app.py", "port": 4800,
                         "operations": [{"name": "go", "risk": "read"}]}})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["id"], "authored")
        ids = [t["id"] for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]]
        self.assertIn("authored", ids)

    def test_add_tool_manifest_must_be_object_400(self):
        r = self.client.post("/api/tools", headers=self._auth(), json={"source": "/x", "manifest": "nope"})
        self.assertEqual(r.status_code, 400)

    def test_tool_source_in_listing_and_update(self):
        src = self._tool_folder("src_wtool", "wtool")
        self.client.post("/api/tools", headers=self._auth(), json={"source": str(src)})
        wtool = next(t for t in self.client.get("/api/tools", headers=self._auth()).json()["tools"]
                     if t["id"] == "wtool")
        self.assertEqual(wtool["source"]["type"], "path")          # provenance surfaced
        r = self.client.post("/api/tools/wtool/update", headers=self._auth())   # re-pull
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["id"], "wtool")

    def test_update_non_tsr_tool_400(self):
        # echo (from setUp) was hand-authored: no .tsr-source.json, so it can't be updated
        r = self.client.post("/api/tools/echo/update", headers=self._auth())
        self.assertEqual(r.status_code, 400)

    def test_update_unknown_tool_404(self):
        self.assertEqual(self.client.post("/api/tools/ghost/update", headers=self._auth()).status_code, 404)

    def test_update_needs_auth(self):
        self.assertEqual(self.client.post("/api/tools/echo/update").status_code, 401)

    # --- secret VALUE provisioning (local vault only) -------------------------
    # The vault needs the 'cryptography' extra (absent from this venv), so VaultBackend is mocked
    # here; the real encrypt/store path is covered by toolyard's vault tests + the demo container.
    def test_secret_endpoints_need_auth(self):
        self.assertEqual(self.client.get("/api/tools/echo/secrets").status_code, 401)
        self.assertEqual(self.client.post("/api/tools/echo/secrets", json={"field": "X", "value": "y"}).status_code, 401)

    # --- per-tool start / stop / restart -------------------------------------
    def test_tool_start_stop_restart(self):
        # mock the toolyard so nothing actually spawns; assert each action is dispatched
        with mock.patch("admin.toolyard_ops.start") as start, \
             mock.patch("admin.toolyard_ops.stop") as stop, \
             mock.patch("admin.toolyard_ops.restart") as restart:
            for action, fn in (("start", start), ("stop", stop), ("restart", restart)):
                r = self.client.post(f"/api/tools/echo/{action}", headers=self._auth())
                self.assertEqual(r.status_code, 200, r.text)
                fn.assert_called_once()
        events = [e["event_type"] for e in self.client.get("/api/audit", headers=self._auth()).json()["audit"]]
        for ev in ("tool_started", "tool_stopped", "tool_restarted"):
            self.assertIn(ev, events)

    def test_tool_action_unknown_400(self):
        self.assertEqual(self.client.post("/api/tools/echo/frobnicate", headers=self._auth()).status_code, 400)

    def test_tool_action_unknown_tool_404(self):
        with mock.patch("admin.toolyard_ops.start"):
            self.assertEqual(self.client.post("/api/tools/ghost/start", headers=self._auth()).status_code, 404)

    def test_tool_action_needs_auth(self):
        self.assertEqual(self.client.post("/api/tools/echo/start").status_code, 401)

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
