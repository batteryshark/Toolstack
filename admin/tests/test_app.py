"""admin.server end-to-end via FastAPI's TestClient: the login + session/CSRF gate,
creating a caller (one-time token), and saving a policy, verified against a real
broker Store. No broker process is started (the supervisor reports 'stopped').

Requires the admin venv (FastAPI + httpx):
    admin/.venv/bin/python -m unittest admin.tests.test_app
"""

import json
import os
import re
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from admin import auth, broker_config, settings, supervisor, toolyard_ops
from admin.broker_config import BrokerRunConfig
from admin.server import create_app
from broker.identity import authenticate
from broker.store import Store

PASSWORD = "hunter2-admin"


def _csrf(html_text: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html_text)
    assert m, "no CSRF token in page"
    return m.group(1)


def _token_from_banner(html_text: str) -> str:
    m = re.search(r"class='token-field' readonly value='([^']+)'", html_text)
    assert m, "no one-time token in banner"
    return m.group(1)


class AdminApp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-app-")
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
            'id = "echo"\ntype = "api"\n\n[entrypoint]\nport = 4601\n\n'
            '[[operations]]\nname = "say"\nrisk = "read"\ndescription = "echo a message"\n',
            encoding="utf-8",
        )
        self.db_path = str(Path(self.tmp, "broker.sqlite3"))
        broker_config.save(BrokerRunConfig(db_path=self.db_path, tools_root=str(Path(self.tmp, "tools"))))

        self.client = TestClient(create_app())

    def _restore_env(self):
        for key, prev in self._env.items():
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev

    def _store(self):
        store = Store(self.db_path)
        self.addCleanup(store.close)
        return store

    def _login(self):
        r = self.client.post("/login", data={"username": "admin", "password": PASSWORD})
        self.assertEqual(r.status_code, 200)  # followed the 303 to the dashboard
        self.assertIn("Toolstack Admin", r.text)

    def test_requires_login(self):
        r = self.client.get("/")
        self.assertIn("Sign in", r.text)

    def test_bad_password_rejected(self):
        r = self.client.post("/login", data={"username": "admin", "password": "wrong"})
        self.assertEqual(r.status_code, 401)
        self.assertIn("Invalid", r.text)

    def test_login_throttled_and_failures_audited(self):
        for _ in range(5):
            r = self.client.post("/login", data={"username": "admin", "password": "wrong"})
            self.assertEqual(r.status_code, 401)
        r = self.client.post("/login", data={"username": "admin", "password": "wrong"})
        self.assertEqual(r.status_code, 429)          # locked out after the per-IP limit
        self.assertIn("retry-after", {k.lower() for k in r.headers})
        events = self._store().recent_audit(limit=20)
        failed = [e for e in events if e["event_type"] == "login_failed"]
        self.assertTrue(failed)                        # failures are audited
        self.assertNotIn("wrong", json.dumps(failed))  # but never the submitted password

    def test_create_caller_and_set_policy(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)

        r = self.client.post("/callers", data={"name": "hermes", "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        token = _token_from_banner(r.text)
        self.assertIsNotNone(authenticate(self._store(), f"Bearer {token}"))

        # A new caller has no tools enabled yet: the policy page is empty and
        # points at the tools page.
        pol = self.client.get("/callers/hermes/policy")
        self.assertNotIn("op__echo__say", pol.text)
        self.assertIn("/callers/hermes/tools", pol.text)

        # Enable echo for this caller on the tools page.
        tools = self.client.get("/callers/hermes/tools")
        self.assertIn("echo", tools.text)
        r = self.client.post("/callers/hermes/tools",
                             data={"tool__echo": "on", "_csrf": _csrf(tools.text)},
                             follow_redirects=False)
        self.assertEqual(r.status_code, 303)

        # Now echo's operations show up on the policy page.
        pol = self.client.get("/callers/hermes/policy")
        self.assertIn("echo", pol.text)
        self.assertIn("say", pol.text)

        r = self.client.post("/callers/hermes/policy",
                             data={"op__echo__say": "review", "_csrf": _csrf(pol.text)},
                             follow_redirects=False)
        self.assertEqual(r.status_code, 303)

        store = self._store()
        caller = store.caller_by_name("hermes")
        self.assertEqual(store.policy_for(caller["id"]),
                         {"tools": {"echo": {"say": "review"}}, "enabled": ["echo"]})
        self.assertTrue(any(e["event_type"] == "policy_changed" for e in store.audit_events()))
        self.assertTrue(any(e["event_type"] == "tools_changed" for e in store.audit_events()))

    def test_rest_tool_path_rule_editor_round_trip(self):
        # a rest tool in the tools root gets the (verb, path, effect) rule editor, not op selects
        kv = Path(self.tmp, "tools", "kv")
        kv.mkdir(parents=True)
        (kv / "toolyard.toml").write_text(
            'id = "kv"\ntype = "rest"\n[entrypoint]\nport = 4621\ncommand = "x"\n'
            '[[operations]]\nname = "GET"\nrisk = "read"\n'
            '[[operations]]\nname = "DELETE"\nrisk = "destructive"\n', encoding="utf-8")
        self._login()
        csrf = _csrf(self.client.get("/").text)
        self.client.post("/callers", data={"name": "hermes", "_csrf": csrf})
        tools = self.client.get("/callers/hermes/tools")
        self.client.post("/callers/hermes/tools",
                         data={"tool__kv": "on", "_csrf": _csrf(tools.text)}, follow_redirects=False)

        pol = self.client.get("/callers/hermes/policy")
        self.assertIn("rules__kv", pol.text)        # the rule-row container
        self.assertIn("POLICY_VERBS", pol.text)      # the JS seed
        self.assertIn("path rules", pol.text)
        self.assertNotIn("op__kv__GET", pol.text)    # NOT the verb-level selects

        rules = json.dumps([
            {"verb": "GET", "pattern": "/items/**", "effect": "allow"},
            {"verb": "GET", "pattern": "/items/secret", "effect": "deny"},   # carve-out
            {"verb": "DELETE", "pattern": "", "effect": "review"},           # bare verb = any path
        ])
        r = self.client.post("/callers/hermes/policy",
                             data={"rest_rules__kv": rules, "_csrf": _csrf(pol.text)},
                             follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        store = self._store()
        kvpol = store.policy_for(store.caller_by_name("hermes")["id"])["tools"]["kv"]
        self.assertEqual(kvpol, {"GET /items/**": "allow", "GET /items/secret": "deny",
                                 "DELETE": "review"})

        # malformed rest_rules JSON (not JSON / non-list / non-dict elements) must degrade, not 500
        for bad in ["not json", '{"x":1}', '["x", 5, null]']:
            r = self.client.post("/callers/hermes/policy",
                                 data={"rest_rules__kv": bad, "_csrf": _csrf(pol.text)},
                                 follow_redirects=False)
            self.assertEqual(r.status_code, 303)

    def test_revoke_token_via_panel(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        token = _token_from_banner(self.client.post("/callers", data={"name": "hermes", "_csrf": csrf}).text)
        self.assertIsNotNone(authenticate(self._store(), f"Bearer {token}"))

        from broker.identity import hash_token
        prefix = hash_token(token)[:12]
        self.client.post("/tokens/revoke", data={"prefix": prefix, "_csrf": csrf})
        self.assertIsNone(authenticate(self._store(), f"Bearer {token}"))

    def test_csrf_required_for_mutations(self):
        self._login()
        r = self.client.post("/callers", data={"name": "ghost"})  # no _csrf
        self.assertIn("Invalid CSRF token", r.text)
        self.assertIsNone(self._store().caller_by_name("ghost"))

    def test_broker_action_requires_csrf(self):
        self._login()
        r = self.client.post("/broker/start", data={})  # no _csrf -> rejected before any spawn
        self.assertIn("Invalid CSRF token", r.text)
        self.assertFalse(supervisor.status()["running"])

    def test_tools_page_lists_defined_tools(self):
        self._login()
        r = self.client.get("/tools")
        self.assertEqual(r.status_code, 200)
        self.assertIn("echo", r.text)

    def test_add_from_source_page_renders(self):
        self._login()
        page = self.client.get("/tools/add")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Add from folder", page.text)
        self.assertIn("Clone and add", page.text)

    def _src_manifest(self, desc, ops):
        op_toml = "".join(f'\n[[operations]]\nname = "{n}"\nrisk = "read"\n' for n in ops)
        return (f'id = "weather"\ntype = "api"\ndescription = "{desc}"\n'
                f'[entrypoint]\ncommand = "x"\nport = 4700\n{op_toml}')

    def test_add_tool_from_folder_then_update(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        src = Path(self.tmp, "src-weather")
        src.mkdir()
        (src / "toolyard.toml").write_text(self._src_manifest("v1", ["today"]), encoding="utf-8")

        r = self.client.post("/tools/add-source",
                             data={"kind": "path", "source": str(src), "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        copied = Path(self.tmp, "tools", "weather", "toolyard.toml")
        self.assertTrue(copied.exists())                       # copied into the tools root
        listing = self.client.get("/tools").text
        self.assertIn("weather", listing)
        self.assertIn("/tools/weather/update-source", listing)  # has a source -> Update button

        # change the source; Update re-pulls its operations/entrypoint
        (src / "toolyard.toml").write_text(self._src_manifest("v2", ["today", "tomorrow"]), encoding="utf-8")
        r = self.client.post("/tools/weather/update-source", data={"_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(tomllib.loads(copied.read_text())["operations"]), 2)

    def test_add_from_folder_without_manifest_guides_to_author(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        empty = Path(self.tmp, "src-empty")
        empty.mkdir()
        r = self.client.post("/tools/add-source",
                             data={"kind": "path", "source": str(empty), "_csrf": csrf})
        self.assertIn("Author a tool", r.text)   # NoManifest -> actionable guidance, not a 500

    def test_bad_tool_degrades_to_banner_not_500(self):
        # A hand-edited tool with no port makes toolyard.config.load raise (T-023); every
        # tool route must degrade to an error banner, never a 500. TestClient re-raises
        # unhandled server errors, so an unguarded 500 would surface as an exception here.
        bad = Path(self.tmp, "tools", "broken")
        bad.mkdir(parents=True)
        (bad / "toolyard.toml").write_text(  # no [entrypoint] port -> load() raises
            'id = "broken"\ntype = "api"\n[entrypoint]\ncommand = "x"\n'
            '[[operations]]\nname = "go"\nrisk = "read"\n', encoding="utf-8")
        self._login()
        csrf = _csrf(self.client.get("/").text)

        self.assertIn("Could not read tools", self.client.get("/tools").text)          # GET list
        self.assertIn("Could not read tools", self.client.get("/tools/echo/edit").text)  # GET editor

        for path, data in (
            ("/tools/echo/edit", {"_csrf": csrf, "tool_json": json.dumps(self._NEW_TOOL)}),  # save
            ("/tools/echo/remove", {"_csrf": csrf}),                                          # remove
            ("/tools/new", {"_csrf": csrf, "dir": str(self.tmp),                              # create
                            "tool_json": json.dumps(self._NEW_TOOL)}),
        ):
            r = self.client.post(path, data=data)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn("Could not read tools", r.text)

    def test_toolyard_action_requires_csrf(self):
        self._login()
        r = self.client.post("/toolyard/tools/echo/start", data={})  # no _csrf -> rejected before spawn
        self.assertIn("Invalid CSRF token", r.text)
        self.assertFalse(toolyard_ops.list_tools(str(Path(self.tmp, "tools")))[0]["running"])

    # --- tool authoring -------------------------------------------------------
    _NEW_TOOL = {
        "id": "weather", "type": "api", "command": "python3 app.py", "image": "", "port": 4700,
        "operations": [{"name": "today", "risk": "read", "description": "today's weather",
                        "args": [{"name": "city", "type": "string", "required": True, "description": ""}]}],
        "secrets": [{"name": "api_key", "field": "API_KEY", "writable": False}],
    }

    def test_tool_editor_requires_login(self):
        self.assertIn("Sign in", self.client.get("/tools/new").text)

    def test_add_tool_writes_toml_and_registers(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        newdir = Path(self.tmp, "newtool")
        newdir.mkdir()
        r = self.client.post("/tools/new", data={
            "dir": str(newdir), "tool_json": json.dumps(self._NEW_TOOL), "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertTrue((newdir / "toolyard.toml").exists())
        self.assertIn(str(newdir), broker_config.load().tool_dirs)
        # the written manifest is consumable by the broker registry
        from broker.registry import Registry
        self.assertIsNotNone(Registry.from_sources(None, [str(newdir)]).lookup("weather", "today"))

    def test_add_tool_rejects_missing_directory(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        r = self.client.post("/tools/new", data={
            "dir": str(Path(self.tmp, "ghost")), "tool_json": json.dumps(self._NEW_TOOL), "_csrf": csrf})
        self.assertIn("does not exist", r.text)
        self.assertEqual(broker_config.load().tool_dirs, [])

    def test_add_tool_rejects_invalid_definition(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        newdir = Path(self.tmp, "newtool2")
        newdir.mkdir()
        bad = {**self._NEW_TOOL, "id": "bad.id"}  # dot is invalid
        r = self.client.post("/tools/new", data={
            "dir": str(newdir), "tool_json": json.dumps(bad), "_csrf": csrf})
        self.assertIn("id must", r.text)
        self.assertFalse((newdir / "toolyard.toml").exists())

    def test_add_rest_tool_without_entrypoint_shows_error_not_500(self):
        # validate() can't run the entrypoint check (it has no directory); write() does and raises.
        # A rest tool with no command/image used to let that ValueError escape as a 500 on save.
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        newdir = Path(self.tmp, "remoteapi")
        newdir.mkdir()
        tool = {"id": "remoteapi", "type": "rest", "command": "", "image": "", "port": 4640,
                "operations": [{"name": "GET"}], "secrets": []}
        r = self.client.post("/tools/new", data={
            "dir": str(newdir), "tool_json": json.dumps(tool), "_csrf": csrf})
        self.assertEqual(r.status_code, 200)                      # form re-rendered, NOT a 500
        self.assertFalse((newdir / "toolyard.toml").exists())     # rejected before writing

    def test_add_proxy_tool_emits_proxy_block_and_auto_assigns_port(self):
        # proxy mode: no operator command/port; the admin auto-fills the wrapper command and a
        # free loopback port, and emits the [proxy] block. This is the "external API" path.
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        newdir = Path(self.tmp, "graphproxy")
        newdir.mkdir()
        tool = {"id": "graphproxy", "type": "rest", "command": "", "image": "",
                "proxy": {"base_url": "https://graph.microsoft.com/v1.0",
                          "inject": [{"into": "header", "name": "Authorization",
                                      "value": "Bearer ${secret:tok}"}],
                          "forward_headers": ["Prefer"]},
                "operations": [{"name": "get_me", "verb": "GET", "path": "/me", "args": []}],
                "secrets": [{"name": "tok", "field": "TOK", "writable": False}]}
        r = self.client.post("/tools/new", data={
            "dir": str(newdir), "tool_json": json.dumps(tool), "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        parsed = tomllib.loads((newdir / "toolyard.toml").read_text())
        self.assertEqual(parsed["proxy"]["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(parsed["entrypoint"]["command"], "python3 -m toolyard.http_proxy")
        self.assertTrue(1 <= parsed["entrypoint"]["port"] <= 65535)   # admin assigned a free port
        self.assertEqual(parsed["proxy"]["inject"][0]["name"], "Authorization")

    def test_add_proxy_tool_rejects_undeclared_secret_ref(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        newdir = Path(self.tmp, "badproxy")
        newdir.mkdir()
        tool = {"id": "badproxy", "type": "rest", "command": "", "image": "",
                "proxy": {"base_url": "https://api.example.com/v1",
                          "inject": [{"into": "header", "name": "Authorization",
                                      "value": "Bearer ${secret:missing}"}]},
                "operations": [{"name": "GET"}], "secrets": []}
        r = self.client.post("/tools/new", data={
            "dir": str(newdir), "tool_json": json.dumps(tool), "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertIn("no matching", r.text)                       # validation error, not a 500
        self.assertFalse((newdir / "toolyard.toml").exists())

    def test_remove_tool_unregisters_but_keeps_files(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        newdir = Path(self.tmp, "removable")
        newdir.mkdir()
        self.client.post("/tools/new", data={
            "dir": str(newdir), "tool_json": json.dumps(self._NEW_TOOL), "_csrf": csrf})
        self.assertIn(str(newdir), broker_config.load().tool_dirs)

        r = self.client.post("/tools/weather/remove", data={"_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(str(newdir), broker_config.load().tool_dirs)
        self.assertTrue((newdir / "toolyard.toml").exists())  # files left on disk

    def test_activity_views_are_filterable(self):
        self._login()
        html = self.client.get("/").text
        self.assertIn("data-filter-for='audit-table'", html)       # audit text filter
        self.assertIn("data-filter-sel='audit-table'", html)       # audit outcome dropdown
        self.assertIn("data-filter-for='requests-table'", html)    # requests text filter
        self.assertIn("All statuses", html)

    def test_remove_root_tool_deletes_its_folder(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        tool_dir = Path(self.tmp, "tools", "echo")
        self.assertTrue(tool_dir.exists())
        r = self.client.post("/tools/echo/remove", data={"_csrf": csrf})  # echo lives under the tools root
        self.assertEqual(r.status_code, 200)
        self.assertIn("Removed tool", r.text)
        self.assertFalse(tool_dir.exists())   # managed tool under the root is deleted, not refused

    def test_edit_tool_rewrites_toml(self):
        self._login()
        page = self.client.get("/tools/echo/edit")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Edit tool", page.text)
        edited = {"id": "echo", "type": "api", "command": "python3 app.py", "image": "", "port": 4601,
                  "operations": [{"name": "say", "risk": "destructive", "description": "changed", "args": []}],
                  "secrets": []}
        r = self.client.post("/tools/echo/edit", data={
            "tool_json": json.dumps(edited), "_csrf": _csrf(page.text)})
        self.assertEqual(r.status_code, 200)
        data = tomllib.loads((Path(self.tmp, "tools", "echo", "toolyard.toml")).read_text())
        self.assertEqual(data["operations"][0]["risk"], "destructive")
        self.assertEqual(data["entrypoint"]["command"], "python3 app.py")


if __name__ == "__main__":
    unittest.main()
