"""admin.server end-to-end via FastAPI's TestClient: the login + session/CSRF gate,
creating a caller (one-time token), and saving a policy — verified against a real
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
    m = re.search(r"shown once: <code>([^<]+)</code>", html_text)
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
            'id = "echo"\ntype = "rest"\n\n[entrypoint]\nport = 4601\n\n'
            '[[operations]]\nname = "say"\nrisk = "low"\ndescription = "echo a message"\n',
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

    def test_create_caller_and_set_policy(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)

        r = self.client.post("/callers", data={"name": "hermes", "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        token = _token_from_banner(r.text)
        self.assertIsNotNone(authenticate(self._store(), f"Bearer {token}"))

        pol = self.client.get("/callers/hermes/policy")
        self.assertIn("echo", pol.text)
        self.assertIn("say", pol.text)

        r = self.client.post("/callers/hermes/policy",
                             data={"op__echo__say": "review", "_csrf": _csrf(pol.text)})
        self.assertEqual(r.status_code, 200)

        store = self._store()
        caller = store.caller_by_name("hermes")
        self.assertEqual(store.policy_for(caller["id"]), {"tools": {"echo": {"say": "review"}}})
        self.assertTrue(any(e["event_type"] == "policy_changed" for e in store.audit_events()))

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

    def test_toolyard_action_requires_csrf(self):
        self._login()
        r = self.client.post("/toolyard/tools/echo/start", data={})  # no _csrf -> rejected before spawn
        self.assertIn("Invalid CSRF token", r.text)
        self.assertFalse(toolyard_ops.list_tools(str(Path(self.tmp, "tools")))[0]["running"])

    # --- tool authoring -------------------------------------------------------
    _NEW_TOOL = {
        "id": "weather", "type": "rest", "command": "python3 app.py", "image": "", "port": 4700,
        "operations": [{"name": "today", "risk": "low", "description": "today's weather",
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

    def test_remove_root_tool_is_refused(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        r = self.client.post("/tools/echo/remove", data={"_csrf": csrf})  # echo lives under the tools root
        self.assertIn("tools root", r.text)

    def test_edit_tool_rewrites_toml(self):
        self._login()
        page = self.client.get("/tools/echo/edit")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Edit tool", page.text)
        edited = {"id": "echo", "type": "rest", "command": "python3 app.py", "image": "", "port": 4601,
                  "operations": [{"name": "say", "risk": "high", "description": "changed", "args": []}],
                  "secrets": []}
        r = self.client.post("/tools/echo/edit", data={
            "tool_json": json.dumps(edited), "_csrf": _csrf(page.text)})
        self.assertEqual(r.status_code, 200)
        data = tomllib.loads((Path(self.tmp, "tools", "echo", "toolyard.toml")).read_text())
        self.assertEqual(data["operations"][0]["risk"], "high")
        self.assertEqual(data["entrypoint"]["command"], "python3 app.py")


if __name__ == "__main__":
    unittest.main()
