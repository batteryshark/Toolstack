"""Security 10/14: synthetic credentials; no real Nod/SPS or external writes."""
import json
import hashlib
import os
import sqlite3
import tempfile
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from broker import approval, request_lifecycle as lifecycle
from broker.approval_summary import summarize, validate_fields, bound_request
from broker.identity import authenticate
from broker.registry import Registry
from broker.store import Store, SCHEMA
from broker.surface_nod import NodSurface
from client import toolstack
from .support import BrokerTestCase, seed_caller
from .test_boundaries import serving


class Summary(BrokerTestCase):
    def test_oversized_first_field_does_not_hide_later_decisive_field(self):
        text = summarize({'a': ['x' * 256] * 16, 'b': 'decisive-fake'}, ('/a', '/b'))
        data = json.loads(text)
        self.assertEqual(data['selected_fields'], [
            {'field': '/a', 'value': '[OMITTED: summary size limit]'},
            {'field': '/b', 'value': 'decisive-fake'}])
        self.assertIn('values shown: 1', text)
        self.assertIn('omitted for summary size: 1', text)
        self.assertLessEqual(len(text), 4000)

    def test_all_oversized_values_are_explicit_even_when_labels_do_not_fit(self):
        for character in ('x', '\u2603'):
            fields = validate_fields(['/' + character * 253 + f'{i:02}' for i in range(32)])
            arguments = {p[1:]: ['x' * 256] * 16 for p in fields}
            text = summarize(arguments, fields)
            self.assertLessEqual(len(text), 4000)
            self.assertIn('ALL configured field values omitted', text)
            self.assertIn('Configured fields: 32; values shown: 0', text)
            self.assertIn('omitted for summary size: 32', text)
            self.assertNotIn('Additional configured', text)
            self.assertTrue(all(e['value'] == '[OMITTED: summary size limit]'
                                for e in json.loads(text)['selected_fields']))

    def test_total_budget_counts_fields_that_cannot_fit_and_keeps_masks(self):
        fields = [f'/field{i}' for i in range(30)] + ['/password', '/reason']
        args = {p[1:]: 'x' * 256 for p in fields}
        args.update(password='fake-private-password', reason='fake-private-justification')
        text = summarize(args, validate_fields(fields))
        self.assertLessEqual(len(text), 4000)
        self.assertIn('omitted for summary size:', text)
        self.assertNotIn('fake-private', text)
        masked = json.loads(summarize(args, ['/password', '/reason']))['selected_fields']
        self.assertEqual([e['value'] for e in masked], ['[MASKED]', '[MASKED]'])

    def test_recursive_short_secret_masks_but_hostname_survives(self):
        text = summarize({"destination": "api.example.com", "body": {
            "password": "tiny", "reason": "tiny-why", "nested": [{"api_key": "abc", "label": "safe"}]}},
            ["/destination", "/body"])
        self.assertIn("api.example.com", text)
        self.assertIn("[MASKED]", text)
        for secret in ("tiny", "tiny-why", "abc"):
            self.assertNotIn(secret, text)
        self.assertIn("safe", text)

    def test_sensitive_ancestor_masks_explicit_child_pointer(self):
        self.assertNotIn("short", summarize({"credentials": {"label": "short"}}, ["/credentials/label"]))

    def test_omitted_decisive_input_and_justification_bound_not_disclosed(self):
        ctx = self.make_ctx(catalog={"fake": {"send": "write"}})
        token = seed_caller(ctx.store, review=["fake.send"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        first = lifecycle.submit(ctx, caller, "fake", "send", {"danger": "x" * 10000 + "decisive"}, "a", reason="short-password")
        second = lifecycle.submit(ctx, caller, "fake", "send", {"danger": "x" * 10000 + "different"}, "b", reason="other")
        card = ctx.surface.opened[0]
        self.assertIn("ALL arguments omitted", card.details)
        self.assertNotIn("decisive", card.details)
        self.assertNotIn("short-password", repr(card))
        self.assertIsNone(card.justification)
        self.assertNotEqual(card.request_digest, ctx.surface.opened[1].request_digest)
        self.assertIn("short-password", ctx.store.request(first.request_id)["action_json"])
        stored = ctx.store.request(first.request_id)["action_json"]
        self.assertEqual(hashlib.sha256(stored.encode()).hexdigest(), card.request_digest)
        self.assertNotIn(json.loads(stored)["nonce"], repr(card))
        self.assertNotIn("short-password", json.dumps(ctx.store.audit_events()))
        ctx.surface.set(approval.APPROVED)
        ctx.registry._catalog["fake"]["port"] = 9999
        self.assertNotEqual(lifecycle.resolve_request(ctx, first.request_id).status, lifecycle.OK)
        self.assertEqual(ctx.runtime.calls, [])

    def test_stored_arguments_changed_after_card_cannot_execute(self):
        ctx = self.make_ctx(catalog={"fake": {"send": "write"}})
        token = seed_caller(ctx.store, review=["fake.send"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        out = lifecycle.submit(ctx, caller, "fake", "send", {"action": "original"}, "a")
        ctx.store.update_request(out.request_id, arguments_json='{"action":"replacement"}')
        ctx.surface.set(approval.APPROVED)
        self.assertEqual(lifecycle.resolve_request(ctx, out.request_id).status, lifecycle.DENIED)
        self.assertEqual(ctx.runtime.calls, [])

    def test_canonical_binding_does_not_confuse_boolean_and_integer(self):
        ctx = self.make_ctx(catalog={"fake": {"send": "write"}})
        token = seed_caller(ctx.store, review=["fake.send"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        out = lifecycle.submit(ctx, caller, "fake", "send", {"value": True}, "a")
        ctx.store.update_request(out.request_id, arguments_json='{"value":1}')
        ctx.surface.set(approval.APPROVED)
        self.assertEqual(lifecycle.resolve_request(ctx, out.request_id).status, lifecycle.DENIED)
        self.assertEqual(ctx.runtime.calls, [])

    def test_replacing_request_binding_cannot_rebind_existing_approval(self):
        ctx = self.make_ctx(catalog={"fake": {"send": "write"}})
        token = seed_caller(ctx.store, review=["fake.send"])
        caller = authenticate(ctx.store, f"Bearer {token}")
        out = lifecycle.submit(ctx, caller, "fake", "send", {"action": "original"}, "a")
        generation = ctx.registry.lookup("fake", "send").generation
        action, digest = bound_request(caller.id, "fake", "send", generation, {"action": "replacement"}, None)
        ctx.store.update_request(out.request_id, arguments_json='{"action":"replacement"}',
                                 action_json=action, request_digest=digest)
        ctx.surface.set(approval.APPROVED)
        self.assertEqual(lifecycle.resolve_request(ctx, out.request_id).status, lifecycle.DENIED)
        self.assertEqual(ctx.runtime.calls, [])

    def test_truncation_nesting_size_and_missing_labels_are_explicit(self):
        text = summarize({"message": "z" * 2000, "items": list(range(100))}, ["/message", "/items", "/missing"])
        self.assertIn("TRUNCATED", text)
        self.assertIn("additional items", text)
        self.assertIn("not present", text)
        self.assertLess(len(text), 6000)

    def test_manifest_pointer_contract_is_loaded_and_described(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "toolyard.toml"
            path.write_text('id="fake"\n[entrypoint]\nport=4600\n[[operations]]\nname="send"\napproval_fields=["/destination","/body/title"]\n')
            catalog = {}
            Registry._add_toml(catalog, path)
            registry = Registry(catalog)
            self.assertEqual(registry.lookup("fake", "send").approval_fields, ("/destination", "/body/title"))
            self.assertEqual(registry.describe("fake", "send")["approval_fields"], ["/destination", "/body/title"])
        self.assertEqual(validate_fields(["/"]), ("/",))
        for bad in ([""], ["/*"], ["/a/*"], ["/literal*key"], ["missing-slash"], ["/bad~2"], ["/x", "/x"], "not-list", ["/x"] * 33):
            with self.assertRaises(ValueError):
                validate_fields(bad)


class NamespaceAndRedirect(unittest.TestCase):
    def test_v1_fixture_upgrades_without_reusing_unbound_approval(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.db")
            old = sqlite3.connect(path)
            old.executescript(SCHEMA)
            old.execute("DROP TABLE broker_metadata")  # actual v1 had no namespace table
            old.execute("ALTER TABLE requests ADD COLUMN operation_generation TEXT")
            old.execute("ALTER TABLE requests ADD COLUMN policy_binding TEXT")
            old.execute("PRAGMA user_version=1")
            old.execute("INSERT INTO callers VALUES (1,'legacy',0,NULL)")
            old.execute("INSERT INTO tokens VALUES ('fake-hash',1,0,NULL)")
            old.execute("INSERT INTO requests(id,correlation_id,caller_id,tool,op,status,arguments_json,created_at,updated_at,operation_generation,policy_binding) VALUES (1,'legacy',1,'fake','send','pending_approval','{}',0,0,'fixture','{}')")
            old.execute("INSERT INTO approvals VALUES (1,1,'old-ref','pending',99999999999,NULL,NULL,NULL,0)")
            old.commit()
            old.close()
            store = Store(path)
            try:
                self.assertEqual(store.caller_name(1), "legacy")
                self.assertEqual(store._conn.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertTrue(store.installation_id)
                self.assertFalse(store.claim_approval(1, "fixture", approval.SurfaceState(approval.APPROVED), 1))
                self.assertEqual(store.request(1)["status"], "denied")
                self.assertIsNone(store.request(1)["arguments_json"])
            finally:
                store.close()

    def test_installation_uuid_persists_across_connections_and_restarts(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.db")
            store = Store(path)
            first = store.installation_id
            other = Store(path)
            try:
                self.assertEqual(other.installation_id, first)
            finally:
                other.close()
                store.close()
            store = Store(path)
            fresh = Store(str(Path(d) / "other.db"))
            try:
                self.assertEqual(store.installation_id, first)
                self.assertNotEqual(fresh.installation_id, first)
            finally:
                store.close()
                fresh.close()

    def test_authenticated_client_and_nod_never_follow_redirect(self):
        hits = []
        class Trap(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")
            def log_message(self, *args):
                pass
        with serving(HTTPServer(("127.0.0.1", 0), Trap)) as target:
            class Redirect(BaseHTTPRequestHandler):
                code = 302
                same_origin = False
                def do_GET(self):
                    if self.path == "/trap":
                        hits.append(self.headers.get("Authorization"))
                        self.send_response(200)
                        self.end_headers()
                        return
                    self.send_response(type(self).code)
                    port = self.server.server_address[1] if type(self).same_origin else target
                    self.send_header("Location", f"http://127.0.0.1:{port}/trap")
                    self.end_headers()
                def log_message(self, *args):
                    pass
            with serving(HTTPServer(("127.0.0.1", 0), Redirect)) as source:
                base = f"http://127.0.0.1:{source}"
                for same_origin in (False, True):
                    Redirect.same_origin = same_origin
                    for code in (301, 302, 303, 307, 308):
                        Redirect.code = code
                        with patch.dict(os.environ, {"TOOLSTACK_URL": base, "TOOLSTACK_TOKEN": "fake-client-token"}):
                            status, body = toolstack._send("GET", "/test")
                            self.assertEqual(status, code)
                            self.assertEqual(body["error"], "redirect_refused")
                        with self.assertRaises(urllib.error.HTTPError) as caught:
                            NodSurface(base, "fake-issuer-token")._call("GET", "/test")
                        caught.exception.close()
            self.assertEqual(hits, [])
