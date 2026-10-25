"""admin.server end-to-end via FastAPI's TestClient: the login + session/CSRF gate,
creating a caller (one-time token), and saving a policy, verified against a real
broker Store. No broker process is started (the supervisor reports 'stopped').

Requires the admin venv (FastAPI + httpx):
    admin/.venv/bin/python -m unittest admin.tests.test_app
"""

import base64
import json
import os
import re
import shutil
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

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


def _has_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


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

        self.client = TestClient(create_app(), base_url="http://127.0.0.1")

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

    def test_password_reset_invalidates_cookie_and_csrf_without_restart(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        settings.write_password_hash(auth.hash_password("replacement-fake"))
        settings.rotate_session_secret()
        self.assertEqual(self.client.get("/", follow_redirects=False).headers["location"], "/login")
        self.assertEqual(self.client.post("/config", data={"_csrf": csrf, "port": "9999"},
                                          follow_redirects=False).headers["location"], "/login")
        self.assertNotEqual(broker_config.load().port, 9999)
        response = self.client.post("/login", data={"username": "admin", "password": "replacement-fake"})
        self.assertIn("Toolstack Admin", response.text)

    def test_create_app_starts_reconciler_when_sps_unconfigured(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_ENV": "/nonexistent/sps.env"}), \
             mock.patch("admin.server.SPSLink") as link, \
             mock.patch("admin.server.start_reconciler_thread") as recon:
            link.from_env.return_value = None
            sentinel = object()
            recon.return_value = sentinel
            app = create_app()
        recon.assert_called_once_with(mock.ANY, None)
        self.assertIs(app.state.reconciler, sentinel)

    def test_create_app_starts_watchdog_when_sps_linked(self):
        with mock.patch.dict(os.environ, {
                "TOOLSTACK_SPS_ENV": "/etc/toolstack/sps.env",
                "TOOLSTACK_SPS_SKIP": "0"}), \
             mock.patch("admin.server.os.path.exists", return_value=True), \
             mock.patch("admin.server.SPSLink") as link, \
             mock.patch("admin.sps_watchdog.SPSWatchdog") as watchdog, \
             mock.patch("admin.server.start_reconciler_thread") as recon:
            link_obj = mock.Mock()
            link_obj.boot_id = mock.Mock()
            link.from_env.return_value = link_obj
            create_app()
        watchdog.assert_called_once()
        watchdog.return_value.start.assert_called_once()
        recon.assert_called_once_with(mock.ANY, link_obj)

    def test_create_app_skips_reconcile_when_sps_configured_but_unavailable(self):
        with mock.patch.dict(os.environ, {
                "TOOLSTACK_SPS_ENV": "/etc/toolstack/sps.env",
                "TOOLSTACK_SPS_SKIP": "0"}), \
             mock.patch("admin.server.os.path.exists", return_value=True), \
             mock.patch("admin.server.SPSLink") as link, \
             mock.patch("admin.server.start_reconciler_thread") as recon:
            link.from_env.return_value = None
            app = create_app()
        recon.assert_not_called()
        self.assertIsNone(app.state.reconciler)

    def test_requires_login(self):
        r = self.client.get("/")
        self.assertIn("Sign in", r.text)

    def test_malformed_and_wrong_purpose_cookie_redirect_to_login(self):
        expiry = str(int(time.time()) + 60)
        secret = settings.session_secret_file().read_text().strip()
        for signature in ("é", auth.csrf_token(expiry, secret)):
            cookie = base64.urlsafe_b64encode(f"csrf|{expiry}|{signature}".encode()).decode()
            self.client.cookies.set("toolstack_admin_session", cookie)
            response = self.client.get("/", follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            self.assertEqual(response.headers["location"], "/login")
        self.client.cookies.clear()
        self._login()
        self.assertIn('name="_csrf"', self.client.get("/").text)

    def test_non_ascii_csrf_rejected_then_current_token_works(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        response = self.client.post("/callers", data={"name": "fake-new", "_csrf": "é"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid CSRF token.", response.text)
        self.assertIsNone(self._store().caller_by_name("fake-new"))
        response = self.client.post("/callers", data={"name": "fake-new", "_csrf": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(self._store().caller_by_name("fake-new"))

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

    def test_web_edits_preserve_unrendered_authority(self):
        self._login()
        csrf = _csrf(self.client.get('/').text)
        self.client.post('/callers', data={'name': 'writer', '_csrf': csrf})
        store = self._store()
        caller = store.caller_by_name('writer')
        store.set_policy(caller['id'], {'enabled': ['echo', 'offline'], 'tools': {
            'echo': {'say': 'allow', 'hidden': 'review'}, 'offline': {'fetch': 'allow'}}})
        response = self.client.post('/callers/writer/policy',
            headers={'Accept': 'application/json'},
            data={'_csrf': csrf, 'op__echo__say': 'deny'})
        self.assertEqual(response.json()['outcome'], 'saved')
        policy = store.policy_for(caller['id'])
        self.assertEqual(policy['tools']['offline'], {'fetch': 'allow'})
        self.assertEqual(policy['tools']['echo']['hidden'], 'review')
        self.assertNotEqual(policy['tools']['echo'].get('say'), 'allow')
        self.client.post('/callers/writer/tools', data={'_csrf': csrf})
        self.assertEqual(store.policy_for(caller['id']), {
            'enabled': ['offline'], 'tools': {'offline': {'fetch': 'allow'}}})

    def test_policy_failed_load_disables_save(self):
        self._login()
        with mock.patch('admin.server.open_store', side_effect=OSError('private path')):
            response = self.client.get('/callers/writer/policy')
        self.assertEqual(response.status_code, 503)
        self.assertIn("type='submit' disabled", response.text)
        self.assertIn('Retry load', response.text)
        self.assertNotIn('private path', response.text)

    def test_add_start_register_are_separate_named_decisions(self):
        self._login()
        csrf = _csrf(self.client.get('/').text)
        source = Path(self.tmp, 'source')
        source.mkdir()
        (source/'toolyard.toml').write_text('id="localfake"\ntype="api"\n[entrypoint]\nport=43212\ncommand="python3 fake.py"\n[[operations]]\nname="read"\nrisk="read"\n')
        with mock.patch('admin.server.toolyard_ops.start') as start, \
             mock.patch('admin.server.supervisor.restart', return_value={'running': True}) as restart:
            added = self.client.post('/tools/add-source', data={'_csrf': csrf, 'kind': 'path', 'source': str(source)})
            self.assertIn('Added localfake', added.text)
            self.assertIn('/toolyard/tools/localfake/start', added.text)
            start.assert_not_called()
            restart.assert_not_called()
            started = self.client.post('/toolyard/tools/localfake/start', data={'_csrf': csrf}, follow_redirects=False)
            self.assertEqual(started.headers['location'], '/tools?tool=localfake')
            start.assert_called_once()
            restart.assert_not_called()
            with mock.patch('admin.catalog_observation.observe_catalog', return_value={'status': 'verified', 'observation_id': 'fake', 'tool_ids': ['localfake']}):
                registered = self.client.post('/broker/restart', data={'_csrf': csrf, 'catalog_target': 'localfake'})
            restart.assert_called_once()
            self.assertIn('localfake · Catalog registration verified', registered.text)

    def test_failed_recovery_retains_named_target_without_replay(self):
        self._login()
        csrf = _csrf(self.client.get('/').text)
        with mock.patch('admin.server.toolyard_ops.restart', side_effect=RuntimeError('private diagnostic')) as restart:
            response = self.client.post('/toolyard/tools/echo/restart', data={'_csrf': csrf})
        restart.assert_called_once()
        self.assertIn('echo · restart outcome unknown', response.text)
        self.assertIn("data-mutation-outcome='unknown'", response.text)
        self.assertIn('/tools?tool=echo', response.text)
        self.assertNotIn('private diagnostic', response.text)

    def test_registration_result_requires_membership_not_cached_listing(self):
        self._login()
        csrf = _csrf(self.client.get('/').text)
        for receipt in ({'status':'verified'}, {'status':'verified','tool_ids':[]},
                        {'status':'verified','tool_ids':['other']}, {'status':'verified','tool_ids':'echo'}):
            with mock.patch('admin.server.supervisor.restart', return_value={'running':True}), \
                 mock.patch('admin.catalog_observation.observe_catalog', return_value=receipt):
                response = self.client.post('/broker/restart', data={'_csrf':csrf,'catalog_target':'echo'})
            self.assertIn('Registration unknown', response.text)
            self.assertNotIn('Catalog registration verified', response.text)
            self.assertNotIn('Catalog verified', response.text)

    def test_policy_after_effect_failure_is_unknown_and_read_does_not_replay(self):
        from broker import operations
        self._login()
        csrf = _csrf(self.client.get('/').text)
        self.client.post('/callers', data={'name': 'writer', '_csrf': csrf})
        self.client.post('/callers/writer/tools', data={'_csrf': csrf, 'tool__echo': 'on'})
        original = operations.set_policy
        def after_effect(*args, **kwargs):
            original(*args, **kwargs)
            raise ValueError('lost completion audit')
        with mock.patch('admin.server.operations.set_policy', side_effect=after_effect) as save:
            response = self.client.post('/callers/writer/policy', headers={'Accept': 'application/json'},
                data={'_csrf': csrf, 'op__echo__say': 'review'})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()['outcome'], 'unknown')
            comparison = self.client.get('/callers/writer/policy')
            self.assertIn("value='review' selected", comparison.text)
            save.assert_called_once()

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

    def test_parse_openapi_returns_forwarder_ops(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        spec = {"openapi": "3.0.0",
                "servers": [{"url": "https://api.example.com/v1"}],
                "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
                "paths": {"/items/{id}": {"get": {"operationId": "getItem",
                          "parameters": [{"name": "id", "in": "path", "required": True}]}}}}
        r = self.client.post("/tools/parse-openapi", data={"spec": json.dumps(spec), "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["base_url"], "https://api.example.com/v1")
        self.assertEqual(body["operations"][0]["name"], "getItem")
        self.assertEqual(body["operations"][0]["path"], "/items/{id}")
        self.assertEqual(body["operations"][0]["args"][0]["name"], "variables")
        self.assertEqual(body["auth_headers"][0]["name"], "Authorization")

    def test_parse_openapi_rejects_bad_json(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        r = self.client.post("/tools/parse-openapi", data={"spec": "{not valid", "_csrf": csrf})
        self.assertEqual(r.status_code, 400)
        self.assertIn("not valid", r.json()["error"].lower())

    @unittest.skipUnless(_has_yaml(), "PyYAML not installed")
    def test_parse_openapi_accepts_yaml(self):
        self._login()
        csrf = _csrf(self.client.get("/tools/new").text)
        spec = ("openapi: 3.0.0\n"
                "servers:\n  - url: https://api.example.com/v1\n"
                "paths:\n  /items/{id}:\n    get:\n      operationId: getItem\n")
        r = self.client.post("/tools/parse-openapi", data={"spec": spec, "_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["operations"][0]["name"], "getItem")

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
        self.assertIn("Clear audit", html)
        self.assertIn("<th>Time</th>", html)

    def test_clear_audit_route_removes_events(self):
        self._login()
        csrf = _csrf(self.client.get("/").text)
        store = self._store()
        self.addCleanup(store.close)
        store.append_audit(123, "admin", "thing_happened", "ok", "corr", None, {})
        self.assertTrue(store.recent_audit())
        r = self.client.post("/audit/clear", data={"_csrf": csrf})
        self.assertEqual(r.status_code, 200)
        events = store.recent_audit()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "audit_cleared")

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
