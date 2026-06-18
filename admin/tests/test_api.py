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

from admin import auth, broker_config, settings
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


if __name__ == "__main__":
    unittest.main()
