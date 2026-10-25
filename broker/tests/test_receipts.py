"""Fake effects and private temporary SQLite state, never automatic replay."""
import concurrent.futures
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from broker import request_lifecycle as life, approval
from broker.audit import AuditLog
from broker.gateway import handle
from broker.identity import authenticate, hash_token
from broker.store import Store
from broker.runtime import NotDispatched
from .support import BrokerTestCase, make_ctx, seed_caller


class Receipts(BrokerTestCase):
    def test_known_non_dispatch_is_failed_and_bad_keys_never_dispatch(self):
        ctx, caller = self.setup_action()
        def refused(*args):
            raise NotDispatched("fake closed local port")
        ctx.runtime.execute = refused
        first = life.submit(ctx, caller, "echo", "say", {}, "a", idempotency_key="known")
        self.assertEqual(first.status, life.FAILED)
        self.assertEqual(life.submit(ctx, caller, "echo", "say", {}, "b", idempotency_key="known").status, life.FAILED)
        for key in ("", "bad key", "*", "x"*129, 1, {"bad": "key"}):
            out = life.submit(ctx, caller, "echo", "say", {}, "bad", idempotency_key=key)
            self.assertEqual(out.status, life.INVALID)
            self.assertIsNone(out.idempotency_key)

    def setup_action(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "read"}})
        token = seed_caller(ctx.store, allow=["echo.say"])
        return ctx, authenticate(ctx.store, f"Bearer {token}")

    def test_matching_retries_conflict_cross_caller_and_generation_behavior(self):
        ctx, caller = self.setup_action()
        first = life.submit(ctx, caller, "echo", "say", {"a": 1, "b": 2}, "a", idempotency_key="retry-1")
        ctx.registry._catalog["echo"]["port"] = 9999
        repeat = life.submit(ctx, caller, "echo", "say", {"b": 2, "a": 1}, "b", idempotency_key="retry-1")
        self.assertEqual((repeat.request_id, repeat.result), (first.request_id, first.result))
        conflict = life.submit(ctx, caller, "echo", "say", {"a": True, "b": 2}, "c", idempotency_key="retry-1")
        self.assertEqual(conflict.status, life.CONFLICT)
        token = seed_caller(ctx.store, "other", allow=["echo.say"])
        other = authenticate(ctx.store, f"Bearer {token}")
        independent = life.submit(ctx, other, "echo", "say", {}, "d", idempotency_key="retry-1")
        self.assertNotEqual(independent.request_id, first.request_id)
        self.assertEqual(len(ctx.runtime.calls), 2)

    def test_private_reason_is_part_of_private_digest(self):
        ctx, caller = self.setup_action()
        life.submit(ctx, caller, "echo", "say", {}, "a", reason="private-short", idempotency_key="key")
        self.assertEqual(life.submit(ctx, caller, "echo", "say", {}, "b", reason="changed", idempotency_key="key").status, life.CONFLICT)
        self.assertNotIn("private-short", json.dumps(ctx.store.audit_events()))

    def test_authority_rechecked_before_sensitive_repeat_and_poll(self):
        ctx, caller = self.setup_action()
        out = life.submit(ctx, caller, "echo", "say", {"private": "test-value"}, "a", idempotency_key="key")
        ctx.store.set_policy(caller.id, {})
        repeat = life.submit(ctx, caller, "echo", "say", {"private": "test-value"}, "b", idempotency_key="key")
        self.assertEqual(repeat.status, life.DENIED)
        self.assertIsNone(repeat.result)
        response = handle("GET", f"/v1/requests/{out.request_id}", {"Authorization": "Bearer token-for-hermes"}, None, ctx)
        self.assertEqual(response.status, 403)
        self.assertNotIn("test-value", json.dumps(response.body))

    def test_historical_completed_receipt_allow_to_review_then_withdraw_and_exact_token_revoke(self):
        ctx, caller = self.setup_action()
        action = "/v1/actions/echo.say"
        payload = {"arguments": {"private": "synthetic-historical-result"}}
        headers = {"Authorization": "Bearer token-for-hermes", "Idempotency-Key": "historical-key"}
        first = handle("POST", action, headers, payload, ctx)
        self.assertEqual(first.status, 200)
        self.assertEqual(first.body["status"], life.OK)
        receipt = f"/v1/requests/{first.body['request_id']}"

        def assert_same_result(auth):
            for method, path, body in (("POST", action, payload), ("GET", receipt, None)):
                response = handle(method, path, {**headers, "Authorization": auth}, body, ctx)
                self.assertEqual(response.status, 200)
                self.assertEqual(response.body["status"], life.OK)
                self.assertEqual(response.body["request_id"], first.body["request_id"])
                self.assertEqual(response.body["result"], first.body["result"])
            self.assertEqual(len(ctx.runtime.calls), 1)
            self.assertEqual(ctx.surface.opened, [])  # review gates NEW effects only

        def assert_withheld(auth, status):
            for method, path, body in (("POST", action, payload), ("GET", receipt, None)):
                response = handle(method, path, {**headers, "Authorization": auth}, body, ctx)
                self.assertEqual(response.status, status)
                self.assertNotIn("result", response.body)
                self.assertNotIn("synthetic-historical-result", json.dumps(response.body))
            self.assertEqual(len(ctx.runtime.calls), 1)

        ctx.store.set_policy(caller.id, {"tools": {"echo": {"say": "review"}}})
        assert_same_result("Bearer token-for-hermes")
        for policy in ({"tools": {"echo": {"say": "deny"}}}, {}):
            with self.subTest(policy=policy):
                ctx.store.set_policy(caller.id, policy)
                assert_withheld("Bearer token-for-hermes", 403)

        ctx.store.set_policy(caller.id, {"tools": {"echo": {"say": "review"}}})
        ctx.store.add_token(caller.id, hash_token("other-active-fake-token"))
        ctx.store.revoke_token(caller.token_hash)
        self.assertEqual(ctx.store.active_token_count(caller.id), 1)
        assert_withheld("Bearer token-for-hermes", 401)
        assert_same_result("Bearer other-active-fake-token")

    def test_immediate_claim_rechecks_token_even_with_other_active_token(self):
        ctx, caller = self.setup_action()
        ctx.store.add_token(caller.id, hash_token("other-active-token"))
        original = ctx.audit.record
        def record(component, event, *args, **kwargs):
            original(component, event, *args, **kwargs)
            if event == "decision_allow":
                ctx.store.revoke_token(caller.token_hash)
        ctx.audit.record = record
        out = life.submit(ctx, caller, "echo", "say", {}, "a", idempotency_key="key")
        self.assertEqual(out.status, life.DENIED)
        self.assertEqual(ctx.runtime.calls, [])

    def test_immediate_claim_rechecks_generation_and_policy(self):
        for mutation in ("policy", "generation"):
            with self.subTest(mutation=mutation):
                ctx, caller = self.setup_action()
                original = ctx.audit.record
                def record(component, event, *args, **kwargs):
                    original(component, event, *args, **kwargs)
                    if event == "decision_allow":
                        if mutation == "policy":
                            ctx.store.set_policy(caller.id, {})
                        else:
                            ctx.registry._catalog["echo"]["port"] = 9999
                ctx.audit.record = record
                self.assertEqual(life.submit(ctx, caller, "echo", "say", {}, "a").status, life.DENIED)
                self.assertEqual(ctx.runtime.calls, [])

    def test_possible_dispatch_timeout_unknown_never_replayed(self):
        ctx, caller = self.setup_action()
        effects = []
        def execute(*args):
            effects.append("effect")
            raise TimeoutError("fake-sensitive-error")
        ctx.runtime.execute = execute
        first = life.submit(ctx, caller, "echo", "say", {}, "a", idempotency_key="key")
        repeat = life.submit(ctx, caller, "echo", "say", {}, "b", idempotency_key="key")
        self.assertEqual((first.status, repeat.status), (life.UNKNOWN, life.UNKNOWN))
        self.assertEqual(first.request_id, repeat.request_id)
        self.assertEqual(effects, ["effect"])
        self.assertNotIn("fake-sensitive-error", repr(first))

    def test_received_is_not_approval_pending_and_key_never_resumes_it(self):
        ctx, caller = self.setup_action()
        op = ctx.registry.lookup("echo", "say")
        req, _, _ = ctx.store.reserve_action(caller, "a", "echo", "say", {}, None, op.generation, "key")
        repeat = life.submit(ctx, caller, "echo", "say", {}, "b", idempotency_key="key")
        self.assertEqual(repeat.status, life.RECEIVED)
        self.assertEqual(req["id"], repeat.request_id)
        self.assertEqual(ctx.runtime.calls, [])

    def test_manual_prune_boundary_tombstones_match_conflict_and_other_caller(self):
        ctx, caller = self.setup_action()
        first = life.submit(ctx, caller, "echo", "say", {}, "a", idempotency_key="key")
        now = time.time()
        cutoff = now - 7 * 86400
        ctx.store._conn.execute("UPDATE requests SET updated_at=? WHERE id=?", (cutoff, first.request_id))
        ctx.store._conn.commit()
        self.assertEqual(ctx.store.prune_payloads(now), 0)
        self.assertEqual(ctx.store.prune_payloads(now + 1), 1)
        self.assertEqual(ctx.store.prune_payloads(now + 2), 0)
        repeat = life.submit(ctx, caller, "echo", "say", {}, "b", idempotency_key="key")
        self.assertEqual(repeat.status, life.RESULT_EXPIRED)
        self.assertTrue(repeat.payloads_pruned)
        self.assertIsNone(repeat.result)
        self.assertEqual(repeat.request_id, first.request_id)
        self.assertEqual(life.submit(ctx, caller, "echo", "say", {"different": 1}, "c", idempotency_key="key").status, life.CONFLICT)
        token = seed_caller(ctx.store, "other", allow=["echo.say"])
        other = authenticate(ctx.store, f"Bearer {token}")
        self.assertEqual(life.submit(ctx, other, "echo", "say", {}, "d", idempotency_key="key").status, life.OK)
        self.assertEqual(len(ctx.runtime.calls), 2)

    def test_active_payloads_never_pruned(self):
        ctx, caller = self.setup_action()
        op = ctx.registry.lookup("echo", "say")
        req, _, _ = ctx.store.reserve_action(caller, "a", "echo", "say", {}, None, op.generation, "key")
        executing, _, _ = ctx.store.reserve_action(caller, "b", "echo", "say", {}, None, op.generation, "executing")
        self.assertTrue(ctx.store.claim_received(executing["id"], op.generation, caller, executing["request_digest"]))
        ctx.store.set_policy(caller.id, {"tools": {"echo": {"say": "review"}}})
        pending = life.submit(ctx, caller, "echo", "say", {}, "c", idempotency_key="pending")
        self.assertEqual(pending.status, life.PENDING)
        self.assertEqual(ctx.store.prune_payloads(time.time() + 30 * 86400), 0)
        for request_id in (req["id"], executing["id"], pending.request_id):
            self.assertIsNotNone(ctx.store.request(request_id)["action_json"])

    def test_http_and_native_mcp_key_contract_conflict409(self):
        ctx, caller = self.setup_action()
        headers = {"Authorization": "Bearer token-for-hermes", "Idempotency-Key": "key"}
        first = handle("POST", "/v1/actions/echo.say", headers, {"arguments": {}}, ctx)
        self.assertEqual(first.body["idempotency_key"], "key")
        self.assertNotIn(ctx.store.request(first.body["request_id"])["payload_digest"], json.dumps(first.body))
        conflict = handle("POST", "/v1/actions/echo.say", headers, {"arguments": {"new": 1}}, ctx)
        self.assertEqual(conflict.status, 409)
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "echo__say", "arguments": {}, "_meta": {"toolstack/idempotency-key": "key"}}}
        reply = handle("POST", "/mcp", {"Authorization": "Bearer token-for-hermes"}, msg, ctx)
        self.assertEqual(json.loads(reply.body["result"]["content"][0]["text"])["request_id"], first.body["request_id"])
        msg["params"]["arguments"] = {"changed": True}
        self.assertEqual(handle("POST", "/mcp", {"Authorization": "Bearer token-for-hermes"}, msg, ctx).status, 409)
        self.assertEqual(len(ctx.runtime.calls), 1)


class ConcurrentReceipts(unittest.TestCase):
    def test_two_store_connections_one_claim_effect_and_offline_reconcile_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.db")
            setup = Store(path)
            token = seed_caller(setup, allow=["echo.say"])
            setup.close()
            barrier = threading.Barrier(2)
            release = threading.Event()
            effects = []
            class Runtime:
                def execute(self, *args):
                    effects.append("effect")
                    if not release.wait(3):
                        raise TimeoutError("test synchronization failed")
                    return {"done": True}
            def submit():
                ctx = make_ctx(catalog={"echo": {"say": "read"}}, runtime=Runtime())
                ctx.store.close()
                ctx.store = Store(path)
                ctx.audit = AuditLog(ctx.store, sink=None)
                try:
                    caller = authenticate(ctx.store, f"Bearer {token}")
                    barrier.wait(timeout=5)
                    out = life.submit(ctx, caller, "echo", "say", {}, "race", idempotency_key="key")
                    if out.status in {life.RECEIVED, life.EXECUTING}:
                        release.set()
                    return out
                finally:
                    ctx.store.close()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(submit) for _ in range(2)]
                results = [future.result(timeout=10) for future in futures]
            self.assertEqual(effects, ["effect"])
            self.assertEqual(results[0].request_id, results[1].request_id)
            self.assertIn(life.OK, {out.status for out in results})
            store = Store(path)
            try:
                caller = authenticate(store, f"Bearer {token}")
                req, _, _ = store.reserve_action(caller, "a", "echo", "say", {}, None, "generation", "stale")
                self.assertTrue(store.claim_received(req["id"], "generation", caller, req["request_digest"]))
                other = Store(path)
                self.assertEqual(other.request(req["id"])["status"], "executing")
                other.close()
                with self.assertRaises(ValueError):
                    store.reconcile_offline()
                self.assertEqual(store.reconcile_offline(confirmed_offline=True), 1)
                self.assertEqual(store.request(req["id"])["status"], "unknown")
                self.assertEqual(effects, ["effect"])
            finally:
                store.close()
