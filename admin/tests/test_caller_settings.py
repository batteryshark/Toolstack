"""Atomic combined settings and revision guards with real SQLite connections."""
import copy
import json
import sqlite3
import time
import unittest
from contextlib import closing
from pathlib import Path

from admin.tests import test_api
from broker import operations, policy
from broker.store import Store


class CallerSettingsTests(unittest.TestCase):
    setUp = test_api.JsonApi.setUp
    _restore_env = test_api.JsonApi._restore_env
    _auth = test_api.JsonApi._auth
    _token = test_api.JsonApi._token

    def seed(self, before=None):
        self.headers = self._auth()
        with closing(Store(self.db_path)) as store:
            caller = store.add_caller("writer-demo")
            store.set_policy(caller, before or {"tools": {"echo": {"say": "review"}}})
        self.url = "/api/callers/writer-demo/settings"
        state = self.client.get(self.url, headers=self.headers)
        self.assertEqual(state.status_code, 200, state.text)
        return state.json()

    def edit(self, state):
        return {"revision": state["revision"], "enabled": [t for t in state["enabled"] if t in state["catalog"]],
                "disabled_functions": {t: [] for t in state["catalog"]},
                "tools": {t: {o["op"]: state["policy"].get("tools", {}).get(t, {}).get(o["op"], "deny")
                              for o in ops} for t, ops in state["catalog"].items()}}

    def test_one_save_gates_functions_and_retains_disabled_policy(self):
        state = self.seed()
        draft = self.edit(state)
        draft["tools"]["echo"]["say"] = "allow"
        draft["disabled_functions"]["echo"] = ["say"]
        response = self.client.put(self.url, headers=self.headers, json=draft)
        self.assertEqual(response.status_code, 200, response.text)
        after = response.json()["policy"]
        self.assertEqual(after["tools"]["echo"]["say"], "allow")
        self.assertEqual(policy.decide(after, "echo", "say"), "deny")
        state = self.client.get(self.url, headers=self.headers).json()
        draft = self.edit(state)
        response = self.client.put(self.url, headers=self.headers, json=draft)
        self.assertEqual(policy.decide(response.json()["policy"], "echo", "say"), "allow")
        state = self.client.get(self.url, headers=self.headers).json()
        draft = self.edit(state); draft["enabled"] = []
        after = self.client.put(self.url, headers=self.headers, json=draft).json()["policy"]
        self.assertEqual(policy.decide(after, "echo", "say"), "deny")
        self.assertEqual(after["tools"]["echo"]["say"], "allow")
        self.assertEqual(operations.enabled_tools(after), [])

    def test_stale_write_has_no_effect_or_audit(self):
        state = self.seed(); draft = self.edit(state)
        with closing(Store(self.db_path)) as store:
            operations.set_policy(store, "writer-demo", ["echo.say"], [], "other")
            count = len(store.recent_audit(500))
        response = self.client.put(self.url, headers=self.headers, json=draft)
        self.assertEqual(response.status_code, 409)
        with closing(Store(self.db_path)) as store:
            self.assertEqual(len(store.recent_audit(500)), count)
            self.assertEqual(store.policy_for(store.caller_by_name("writer-demo")["id"])["tools"]["echo"]["say"], "allow")

    def test_preserves_unseen_tools_operations_and_future_metadata(self):
        state = self.seed({"enabled": ["echo", "offline"], "tools": {"echo": {"say": "review", "retired": "allow"}, "offline": {"op": "review"}},
                           "disabled_functions": {"echo": ["retired"], "offline": ["gone"]}, "future": {"keep": True}})
        draft = self.edit(state); draft["tools"]["echo"]["say"] = "deny"
        after = self.client.put(self.url, headers=self.headers, json=draft).json()["policy"]
        self.assertEqual(after["enabled"], ["echo", "offline"])
        self.assertEqual(after["tools"]["echo"]["retired"], "allow")
        self.assertEqual(after["tools"]["offline"], {"op": "review"})
        self.assertEqual(after["disabled_functions"], {"echo": ["retired"], "offline": ["gone"]})
        self.assertEqual(after["future"], {"keep": True})

    def test_invalid_payload_never_partially_writes(self):
        state = self.seed(); good = self.edit(state)
        for field, value in (("enabled", ["unknown"]), ("enabled", "echo"), ("tools", {"echo": {"say": "permit"}}),
                             ("tools", {}), ("disabled_functions", {"echo": ["gone"]}), ("disabled_functions", [])):
            draft = copy.deepcopy(good); draft[field] = value
            response = self.client.put(self.url, headers=self.headers, json=draft)
            self.assertIn(response.status_code, (400, 409), response.text)
            self.assertEqual(self.client.get(self.url, headers=self.headers).json()["revision"], state["revision"])

    def test_catalog_change_blocks_old_draft(self):
        state = self.seed(); draft = self.edit(state)
        path = Path(self.tmp, "tools/echo/toolyard.toml")
        path.write_text(path.read_text() + '\n[[operations]]\nname="new_op"\nrisk="read"\ndescription="new"\n')
        self.assertEqual(self.client.put(self.url, headers=self.headers, json=draft).status_code, 409)

    def test_revoked_caller_cannot_save(self):
        state = self.seed(); draft = self.edit(state)
        with closing(Store(self.db_path)) as store: store.revoke_caller("writer-demo")
        self.assertEqual(self.client.put(self.url, headers=self.headers, json=draft).status_code, 404)

    def test_database_compare_and_swap_closes_the_read_write_race(self):
        self.seed()
        with closing(Store(self.db_path)) as first, closing(Store(self.db_path)) as second:
            caller = first.caller_by_name("writer-demo")["id"]
            before = first.policy_for(caller)
            changed = {"enabled": [], "tools": before["tools"]}
            self.assertTrue(first.compare_and_set_policy(caller, before, changed, "one"))
            self.assertFalse(second.compare_and_set_policy(caller, before, {"tools": {}}, "two"))
            self.assertEqual(second.policy_for(caller), changed)

    def test_audit_failure_rolls_back_policy_and_invalidation(self):
        self.seed()
        with closing(Store(self.db_path)) as store:
            caller = store.caller_by_name("writer-demo")["id"]; before = store.policy_for(caller)
            request = store.create_request("fake-approval", caller, "echo", "say", "pending_approval")
            store.create_approval(request, "fake-card", time.time() + 300)
            store._conn.execute("CREATE TRIGGER fail_settings BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'fake full disk'); END")
            store._conn.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                store.compare_and_set_policy(caller, before, {"enabled": [], "tools": {}}, "operator")
            self.assertEqual(store.policy_for(caller), before)
            self.assertEqual(store.request(request)["status"], "pending_approval")
            self.assertEqual(store.approval_for_request(request)["status"], "pending")

    def test_combined_save_invalidates_pending_approval_in_the_same_commit(self):
        state = self.seed(); draft = self.edit(state)
        with closing(Store(self.db_path)) as store:
            caller = store.caller_by_name("writer-demo")["id"]
            request = store.create_request("fake-approval", caller, "echo", "say", "pending_approval")
            store.create_approval(request, "fake-card", time.time() + 300)
        draft["tools"]["echo"]["say"] = "allow"
        self.assertEqual(self.client.put(self.url, headers=self.headers, json=draft).status_code, 200)
        with closing(Store(self.db_path)) as store:
            self.assertEqual(store.policy_for(caller)["tools"]["echo"]["say"], "allow")
            self.assertEqual(store.request(request)["status"], "denied")
            self.assertEqual(store.approval_for_request(request)["status"], "cancelled")
            self.assertEqual(len(store.recent_audit(500)), 1)

    def test_legacy_mutations_keep_function_exclusions(self):
        self.seed({"enabled": ["echo"], "tools": {"echo": {"say": "allow"}}, "disabled_functions": {"echo": ["say"]}})
        with closing(Store(self.db_path)) as store:
            operations.set_policy(store, "writer-demo", ["echo.say"], [], "operator")
            caller = store.caller_by_name("writer-demo")["id"]
            self.assertEqual(policy.decide(store.policy_for(caller), "echo", "say"), "deny")
            operations.set_enabled_tools(store, "writer-demo", [], "operator")
            self.assertEqual(store.policy_for(caller)["enabled"], [])

    def test_web_settings_uses_cookie_csrf_not_bearer_authority(self):
        self.seed()
        url = "/callers/writer-demo/settings"
        self.assertEqual(self.client.get(url, headers=self.headers, follow_redirects=False).status_code, 303)
        self.assertEqual(self.client.post(url, headers=self.headers, data={}).status_code, 401)
        self.client.post("/login", data={"username": "admin", "password": test_api.PASSWORD})
        state = self.client.get(url, headers={"Accept": "application/json"}).json()
        draft = self.edit(state)
        self.assertNotIn("csrf", self.client.get(self.url, headers=self.headers).json())
        self.assertEqual(self.client.post(url, data={"settings_json": json.dumps(draft)}).status_code, 403)
        response = self.client.post(url, data={"_csrf": state["csrf"], "settings_json": json.dumps(draft)})
        self.assertEqual(response.status_code, 200, response.text)

    def test_30_tools_by_20_functions_commit_together(self):
        for index in range(30):
            tool = "echo" if index == 0 else f"tool{index:02}"
            directory = Path(self.tmp, "tools", tool); directory.mkdir(exist_ok=True)
            content = f'id="{tool}"\ntype="api"\n[entrypoint]\ncommand="never-run"\nport={4601 + index}\n'
            content += "".join(f'\n[[operations]]\nname="fn{op:02}"\nrisk="read"\ndescription="Fake function"\n' for op in range(20))
            (directory / "toolyard.toml").write_text(content)
        state = self.seed(); draft = self.edit(state)
        self.assertEqual(len(state["catalog"]), 30)
        self.assertEqual(sum(map(len, state["catalog"].values())), 600)
        draft["enabled"] = list(state["catalog"])
        for tool in draft["tools"]:
            draft["tools"][tool]["fn01"] = "review"
            draft["disabled_functions"][tool] = ["fn02"]
        result = self.client.put(self.url, headers=self.headers, json=draft)
        self.assertEqual(result.status_code, 200, result.text)
        after = result.json()["policy"]
        for tool in state["catalog"]:
            self.assertEqual(policy.decide(after, tool, "fn01"), "review")
            self.assertEqual(policy.decide(after, tool, "fn02"), "deny")
        with closing(Store(self.db_path)) as store:
            self.assertEqual([event["event_type"] for event in store.recent_audit(500)], ["settings_changed"])
