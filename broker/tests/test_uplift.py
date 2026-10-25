"""Focused uplift regressions; fake credentials and temporary state only."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from broker import approval, request_lifecycle as lifecycle
from broker.identity import authenticate
from broker.registry import Registry
from broker import operations
from broker.store import Store
from broker.tool_state import ToolState
from .support import BrokerTestCase, seed_caller


class Claim(BrokerTestCase):
    def scenario(self, mutate):
        ctx = self.make_ctx(catalog={"echo": {"say": "low"}})
        token = seed_caller(ctx.store, review=["echo.say"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        out = lifecycle.submit(ctx, caller, "echo", "say", {"secret": "fake"}, "test")
        def poll(ref):
            mutate(ctx, out.request_id)
            return approval.SurfaceState(approval.APPROVED)
        ctx.surface.poll = poll
        result = lifecycle.resolve_request(ctx, out.request_id)
        self.assertNotEqual(result.status, lifecycle.OK)
        self.assertEqual(ctx.runtime.calls, [])

    def test_revoke_during_poll(self):
        self.scenario(lambda ctx, rid: ctx.store.revoke_caller("hermes"))

    def test_cancel_during_poll(self):
        self.scenario(lambda ctx, rid: ctx.store.update_request(rid, status="denied", arguments_json=None))

    def test_policy_change_during_poll(self):
        self.scenario(lambda ctx, rid: ctx.store.set_policy(1, {}))

    def test_generation_change_during_poll(self):
        self.scenario(lambda ctx, rid: ctx.registry._catalog["echo"].update(port=9999))

    def test_deadline_passes_during_poll(self):
        def expire(ctx, rid):
            ctx.store._conn.execute("UPDATE approvals SET expires_at=? WHERE request_id=?", (time.time()-1, rid))
            ctx.store._conn.commit()
        self.scenario(expire)


class State(unittest.TestCase):
    def test_grant_delta_is_audited_without_values(self):
        store = Store(":memory:")
        try:
            seed_caller(store, allow=["echo.say"])
            operations.set_policy(store, "hermes", [], ["echo.say"], "test")
            event = store.audit_events()[-1]
            self.assertEqual(event["details"]["grant_delta"], [
                {"operation": "echo.say", "before": "allow", "after": "review"}])
        finally:
            store.close()

    def test_schema_migration_is_repeatable(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.sqlite3")
            store = Store(path)
            store.close()
            store = Store(path)
            try:
                self.assertEqual(store._conn.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertIn("operation_generation", {r[1] for r in store._conn.execute("PRAGMA table_info(requests)")})
            finally:
                store.close()

    def test_manifest_drift_fails_lookup_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "toolyard.toml"
            path.write_text('id="echo"\n[entrypoint]\nport=4600\n[[operations]]\nname="say"\n')
            catalog = {}
            Registry._add_toml(catalog, path)
            registry = Registry(catalog)
            self.assertIsNotNone(registry.lookup("echo", "say"))
            path.write_text(path.read_text().replace("4600", "4601"))
            self.assertIsNone(registry.lookup("echo", "say"))

    def test_private_db_and_sidecars(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "private" / "broker.sqlite3")
            store = Store(path)
            store.add_caller("sidecar-fixture")
            try:
                self.assertEqual(os.stat(Path(path).parent).st_mode & 0o777, 0o700)
                for candidate in (path, path + "-wal", path + "-shm"):
                    self.assertEqual(os.stat(candidate).st_mode & 0o777, 0o600)
            finally:
                store.close()

    def test_channel_path_never_private_state(self):
        with tempfile.TemporaryDirectory() as d:
            private = Path(d) / "state.json"
            private.write_text(json.dumps({"x": {"e_secret": "fake-private"}}))
            with patch.dict(os.environ, {"TOOLSTACK_TOOLYARD_STATE": str(private)}, clear=True):
                self.assertIsNone(ToolState().channel_secret_for("x"))
                private.with_name("channels.json").write_text(json.dumps({"x": {"channel_secret": "fake-channel"}}))
                self.assertEqual(ToolState().channel_secret_for("x"), "fake-channel")

    def test_prefix_rejects_wildcards_and_short_values(self):
        store = Store(":memory:")
        try:
            for prefix in ("%", "_", "abcd", "a"*11, "A"*12, "g"*12):
                for fn in (store.revoke_token_by_prefix, store.caller_ids_for_token_prefix):
                    with self.assertRaises(ValueError):
                        fn(prefix)
        finally:
            store.close()

    def test_duplicate_invalid_and_reserved_operation(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "toolyard.toml"
            for operations, secrets in ((["say", "say"], False), (["bad/name"], False), (["refresh"], True)):
                text = 'id="echo"\n[entrypoint]\nport=4600\n'
                text += ''.join(f'[[operations]]\nname="{op}"\n' for op in operations)
                if secrets:
                    text += '[[secrets]]\nname="fake"\n'
                path.write_text(text)
                with self.assertRaises(ValueError):
                    Registry._add_toml({}, path)
