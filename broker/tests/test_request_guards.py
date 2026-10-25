"""Input admission and approval receipt regressions with fake transports."""
import io
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock

from broker import approval, mcp
from broker.gateway import handle
from broker.ratelimit import RateLimiter
from broker.server import _Handler, MAX_BODY_BYTES
from .support import BrokerTestCase, seed_caller


class RequestGuards(BrokerTestCase):
    def test_large_body_authentication_precedes_read(self):
        ctx = self.make_ctx()
        token = seed_caller(ctx.store)
        handler = object.__new__(_Handler)
        handler.server = SimpleNamespace(ctx=ctx)
        handler.path = "/v1/actions/echo.say"
        handler.headers = Message()
        handler.headers["Content-Length"] = str(MAX_BODY_BYTES + 1)
        handler.rfile = Mock()
        with self.assertRaises(PermissionError):
            handler._read_body()
        handler.rfile.read.assert_not_called()
        handler.headers["Authorization"] = f"Bearer {token}"
        handler.rfile = io.BytesIO(b" " * (MAX_BODY_BYTES - 1) + b"{}")
        self.assertEqual(handler._read_body(), {})

    def test_invalid_names_never_reserve_or_lookup(self):
        ctx = self.make_ctx()
        token = seed_caller(ctx.store)
        headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "fake-key"}
        for name in ("echo.bad/name", "echo.bad%00", "-echo.say", "echo.\n"):
            response = handle("POST", "/v1/actions/" + name, headers, {}, ctx)
            self.assertEqual(response.status, 400)
        for name in ("echo__bad/name", "-echo__say", "echo__bad%00"):
            self.assertEqual(mcp._resolve_name(ctx, name), (None, None))
        self.assertEqual(ctx.store.list_requests(), [])
        self.assertFalse(any(e["event_type"] == "tool_lookup_failed" for e in ctx.audit.events()))
        self.assertNotIn("bad/name", str(ctx.audit.events()))

    def test_status_polls_are_metered_before_surface_contact(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "read"}})
        token = seed_caller(ctx.store, review=["echo.say"])
        headers = {"Authorization": f"Bearer {token}"}
        response = handle("POST", "/v1/actions/echo.say", headers, {}, ctx)
        path = f'/v1/requests/{response.body["request_id"]}'
        ctx.rate_limiter = RateLimiter(1)
        ctx.surface.poll = Mock(wraps=ctx.surface.poll)
        self.assertEqual(handle("GET", path, headers, {}, ctx).status, 200)
        self.assertEqual(handle("GET", path, headers, {}, ctx).status, 429)
        ctx.surface.poll.assert_called_once()

    def test_approval_note_is_masked_in_storage_and_receipt(self):
        for outcome in (approval.APPROVED, approval.REJECTED):
            ctx = self.make_ctx(catalog={"echo": {"say": "read"}})
            token = seed_caller(ctx.store, review=["echo.say"])
            headers = {"Authorization": f"Bearer {token}"}
            response = handle("POST", "/v1/actions/echo.say", headers, {}, ctx)
            rid = response.body["request_id"]
            ctx.surface.set(outcome, note="Bearer fake-secret " + "words " * 200)
            receipt = handle("GET", f"/v1/requests/{rid}", headers, {}, ctx)
            note = ctx.store.approval_for_request(rid)["note"]
            self.assertNotIn("fake-secret", note)
            self.assertLessEqual(len(note), 283)
            self.assertIn("[redacted]", note)
            self.assertNotIn("fake-secret", str(receipt.body))
