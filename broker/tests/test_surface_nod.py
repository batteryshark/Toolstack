"""NodSurface HTTP adapter: maps an OperationCard to nod's create request (issuer
token, no raw args, redacted push) and maps nod's decision back to a SurfaceState.

The fake below is wire-faithful to nod v1.0.1 (nod-proto @ 01d535d): it enforces
the real create-body contract (`deny_unknown_fields`, required `title`) and
returns the real response shapes. So if the adapter starts sending a field nod
would reject, or stops reading one nod actually returns, these tests fail.
For a check against a *real* nod server, see test_surface_nod_live.py."""

import json
import subprocess
import sys
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from broker import approval
from broker.approval import OperationCard
from broker.surface_nod import NodSurface

CARD = OperationCard(
    request_id=7, title="Approve echo.shout for caller hermes",
    caller="hermes", tool="echo", op="shout", risk="destructive", reason="policy review",
    installation_id="10000000-0000-4000-8000-000000000001",
)

# nod v1.0.1 CreateDecisionRequest accepts exactly these top-level fields
# (nod-proto/src/request.rs, `#[serde(deny_unknown_fields)]`). Anything else is a
# 400 from the real server, so the fake rejects it too.
NOD_CREATE_FIELDS = {
    "channel_id", "recipients", "decision_resolution", "title", "summary",
    "body_markdown", "fields", "links", "image_url", "notification",
    "dedupe_key", "expires_at", "options", "callback_url",
    # api-layer CreateRequestRequest also accepts these template passthroughs:
    "template_id", "template_version", "variables",
}
# nod v1.0.1 OptionKind, snake_case (nod-proto/src/request.rs).
NOD_OPTION_KINDS = {
    "approve", "approve_with_text", "reject", "reject_with_text",
    "dismiss", "open", "custom",
}


class _FakeNod(BaseHTTPRequestHandler):
    created = None
    decision = None       # None = pending; else the decision-read body
    last_reject = None     # records a contract violation the fake caught

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        if self.path == "/api/v1/requests":
            # Mirror nod's strict create contract.
            unknown = set(body) - NOD_CREATE_FIELDS
            if unknown:
                type(self).last_reject = f"unknown fields: {sorted(unknown)}"
                return self._send(400, {"error": "unknown_field"})
            if not body.get("title"):
                type(self).last_reject = "missing title"
                return self._send(400, {"error": "missing_title"})
            for opt in body.get("options", []):
                if opt.get("kind") not in NOD_OPTION_KINDS:
                    type(self).last_reject = f"bad option kind: {opt.get('kind')}"
                    return self._send(400, {"error": "bad_option_kind"})
            type(self).created = {"auth": self.headers.get("Authorization"), "body": body}
            # Real create response shape: {request_id, deduped, request{...}}.
            return self._send(200, {
                "request_id": "nod-123",
                "deduped": False,
                "request": {"id": "nod-123", "request_id": "nod-123",
                            "status": "pending", "title": body["title"]},
            })
        if self.path.endswith("/cancel"):
            # Real cancel returns the request; adapter ignores the body.
            return self._send(200, {"request": {"id": "nod-123", "status": "cancelled"}})
        return self._send(404, {"error": "nf"})

    def do_GET(self):
        if self.path == "/api/v1/requests/nod-123/decision":
            body = type(self).decision or _pending_view()
            return self._send(200, body)
        return self._send(404, {"error": "nf"})

    def _send(self, status, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def _pending_view():
    """A real nod RequestDecisionView for a still-pending request."""
    return {"request_id": "nod-123", "status": "pending", "decision": None,
            "decisions": [], "decision_resolution": "shared",
            "recipients": ["owner"], "pending_recipients": ["owner"],
            "request_digest": "abc"}


def _resolved_view(option_kind, *, text=None, actor="owner"):
    """A real nod RequestDecisionView for a resolved request."""
    return {"request_id": "nod-123", "status": "resolved",
            "decision": {"request_id": "nod-123", "option_id": "reject" if option_kind.startswith("reject") else "approve",
                         "option_kind": option_kind, "option_label": option_kind.title(),
                         "text": text, "actor_user_id": actor,
                         "actor_device_id": "device-1", "signature": None,
                         "resolved_at": "2026-06-17T00:00:00.000Z"},
            "decisions": [], "decision_resolution": "shared",
            "recipients": ["owner"], "pending_recipients": [],
            "request_digest": "abc"}


class NodSurfaceHTTP(unittest.TestCase):
    def setUp(self):
        _FakeNod.created = None
        _FakeNod.decision = None
        _FakeNod.last_reject = None
        self.server = HTTPServer(("127.0.0.1", 0), _FakeNod)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.surface = NodSurface(f"http://127.0.0.1:{self.port}", "issuer-tok")

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def test_open_posts_redacted_card_with_issuer_token(self):
        ref = self.surface.open(CARD)
        self.assertEqual(ref, "nod-123")
        self.assertIsNone(_FakeNod.last_reject)  # passed nod's strict create contract
        self.assertEqual(_FakeNod.created["auth"], "Bearer issuer-tok")
        body = _FakeNod.created["body"]
        self.assertEqual(body["dedupe_key"], "toolstack:10000000-0000-4000-8000-000000000001:7")
        self.assertEqual(body["title"], CARD.title)
        self.assertTrue(body["notification"]["redact"])
        self.assertNotIn("arguments", body)  # no raw args in the card

    def test_open_includes_redacted_request_in_body_markdown(self):
        card = OperationCard(
            request_id=7, title="Approve echo.shout for caller hermes", caller="hermes",
            tool="echo", op="shout", risk="write", reason="policy review",
            installation_id=CARD.installation_id,
            details='{\n  "body": {\n    "dueDate": "2026-07-01"\n  }\n}')
        self.surface.open(card)
        body = _FakeNod.created["body"]
        self.assertIn("2026-07-01", body["body_markdown"])
        self.assertEqual(set(body) - NOD_CREATE_FIELDS, set())

    def test_open_includes_endpoint_field_when_present(self):
        card = OperationCard(
            request_id=7, title="Approve jira.login for caller hermes", caller="hermes",
            tool="jira", op="login", risk="write", reason="policy review",
            endpoint="POST api.example.test /login",
            installation_id=CARD.installation_id,
        )
        self.surface.open(card)
        fields = {f["label"]: f["value"] for f in _FakeNod.created["body"]["fields"]}
        self.assertEqual(fields["Endpoint"], "POST api.example.test /login")

    def test_open_omits_endpoint_field_for_api_tools(self):
        self.surface.open(CARD)
        fields = {f["label"]: f["value"] for f in _FakeNod.created["body"]["fields"]}
        self.assertNotIn("Endpoint", fields)

    def test_open_payload_obeys_nod_create_contract(self):
        """Every field the adapter sends is one nod actually accepts, and every
        option kind is a real OptionKind, the doc-vs-code drift this task closed."""
        self.surface.open(CARD)
        body = _FakeNod.created["body"]
        self.assertEqual(set(body) - NOD_CREATE_FIELDS, set())
        for opt in body["options"]:
            self.assertIn(opt["kind"], NOD_OPTION_KINDS)

    def test_open_never_sends_callback_url(self):
        # Resolution is poll-only by design: nod posts callbacks unauthenticated,
        # so a broker receiver would let anyone forge an approval. The adapter must
        # never register a callback_url. (nod still *accepts* the field; this is a
        # deliberate choice on our side, not a contract limit.)
        self.surface.open(CARD)
        self.assertNotIn("callback_url", _FakeNod.created["body"])

    def test_open_never_discloses_free_text_justification(self):
        from dataclasses import replace
        self.surface.open(replace(CARD, justification="tiny-password"))
        self.assertNotIn("tiny-password", json.dumps(_FakeNod.created["body"]))

    def test_poll_pending(self):
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.PENDING)

    def test_poll_approved(self):
        _FakeNod.decision = _resolved_view("approve")
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.APPROVED)
        self.assertEqual(state.approver, "owner")
        self.assertEqual(state.decided_at, "2026-06-17T00:00:00.000Z")  # nod resolved_at

    def test_only_exact_issued_pair_and_resolved_status_can_approve(self):
        for status, option_id, kind in (("pending", "approve", "approve"),
                                        ("RESOLVED", "approve", "approve"),
                                        ("resolved", "other", "approve"),
                                        ("resolved", "approve", "approve_extra"),
                                        ("resolved", "approve", "APPROVE"),
                                        ("resolved", "reject", "reject")):
            with self.subTest(status=status, option_id=option_id, kind=kind):
                body = _resolved_view("approve")
                body["status"] = status
                body["decision"].update(option_id=option_id, option_kind=kind)
                _FakeNod.decision = body
                self.assertEqual(self.surface.poll("nod-123").outcome, approval.PENDING)

    def test_mismatched_top_and_any_returned_nested_request_ids_are_refused(self):
        for where in ("top", "decision", "per_user", "request"):
            with self.subTest(where=where):
                body = _resolved_view("approve")
                if where == "top":
                    body["request_id"] = "other"
                elif where == "decision":
                    body["decision"]["request_id"] = "other"
                elif where == "per_user":
                    body["decisions"] = [{"user_id": "owner", "decision": {"request_id": "other"}}]
                else:
                    body["request"] = {"id": "other"}
                _FakeNod.decision = body
                with self.assertRaises(ValueError):
                    self.surface.poll("nod-123")

    def test_absent_optional_nested_request_does_not_invent_wire_fields(self):
        body = _resolved_view("approve")
        self.assertNotIn("request", body)  # v1.0.1 RequestDecisionView has no request wrapper
        _FakeNod.decision = body
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.APPROVED)

    def test_open_mismatched_nested_request_identifier_is_refused(self):
        from unittest.mock import patch
        with patch.object(self.surface, "_call", return_value={"request_id": "nod-123", "request": {"id": "other"}}):
            with self.assertRaises(ValueError):
                self.surface.open(CARD)

    def test_poll_approved_with_text(self):
        _FakeNod.decision = _resolved_view("approve_with_text", text="lgtm")
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.PENDING)  # kind was never issued

    def test_poll_rejected(self):
        _FakeNod.decision = _resolved_view("reject_with_text", text="nope")
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.REJECTED)
        self.assertEqual(state.note, "nope")

    def test_poll_dismiss_is_not_an_approval(self):
        _FakeNod.decision = _resolved_view("dismiss")
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.PENDING)

    def test_poll_expired(self):
        _FakeNod.decision = {"request_id": "nod-123", "status": "expired", "decision": None}
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.EXPIRED)

    def test_poll_cancelled(self):
        _FakeNod.decision = {"request_id": "nod-123", "status": "cancelled", "decision": None}
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.CANCELLED)

    def test_cancel_is_best_effort(self):
        # Returns None and does not raise, even though nod replies with a body.
        self.assertIsNone(self.surface.cancel("nod-123"))


class NodOriginIsolation(unittest.TestCase):
    def test_invalid_base_urls_refused_before_contact_with_generic_error(self):
        from broker.surface_nod import _OPENER
        with patch.object(_OPENER, 'open') as contact:
            for url in ('file:///fake-private', 'ftp://example.test', 'http:///missing',
                        'https://', 'https://fake-user:fake-pass@example.test',
                        'http://example.test?fake-token', 'http://example.test#fake-token',
                        'http://example.test?', 'http://example.test#',
                        'http://example.test:invalid', 'http://example.test:65536',
                        'http://example.test:0', 'http://[bad', ' http://example.test',
                        'http://example.test/\nfake', 'http://example.test\\fake', None):
                with self.subTest(url=url), self.assertRaises(ValueError) as caught:
                    NodSurface(url, 'fake-issuer-only')
                self.assertEqual(str(caught.exception), 'invalid Nod base URL')
            contact.assert_not_called()

    @contextmanager
    def serving(self, handler):
        class Bounded(handler):
            def setup(self):
                self.request.settimeout(2)
                super().setup()
        server = HTTPServer(('127.0.0.1', 0), Bounded)
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        worker.start()
        try:
            yield server.server_address[1], Bounded
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(server.socket.fileno(), -1)

    def test_import_time_proxy_ignored_for_normal_reverse_proxy_path_flow(self):
        class FakeNod(_FakeNod):
            received = []
            decision = _resolved_view('approve')

            def record(self):
                self.received.append((self.path, self.headers.get('Authorization')))
                if self.path.startswith('/nod/'):
                    self.path = self.path[len('/nod'):]

            def do_POST(self):
                self.record()
                super().do_POST()

            def do_GET(self):
                self.record()
                super().do_GET()

        class ProxyTrap(BaseHTTPRequestHandler):
            received = []

            def do_POST(self):
                self.received.append((self.path, self.headers.get('Authorization'),
                                      self.rfile.read(int(self.headers.get('Content-Length', '0')))))
                self.send_response(502)
                self.send_header('Content-Length', '0')
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *args):
                pass

        probe = '''
import sys, urllib.request
assert urllib.request.getproxies()['http'] == sys.argv[2]
assert not urllib.request.proxy_bypass('127.0.0.1')
from broker.surface_nod import NodSurface, _OPENER, _NoRedirect
from broker.bounds import DeadlineHTTPHandler, DeadlineHTTPSHandler
from broker.tests.test_surface_nod import CARD
from broker import approval
surface = NodSurface(sys.argv[1], 'fake-issuer-only', timeout=2)
ref = surface.open(CARD)
assert ref == 'nod-123'
assert surface.poll(ref).outcome == approval.APPROVED
surface.cancel(ref)
assert any(isinstance(h, _NoRedirect) for h in _OPENER.handlers)
assert any(isinstance(h, DeadlineHTTPHandler) for h in _OPENER.handlers)
assert any(isinstance(h, DeadlineHTTPSHandler) for h in _OPENER.handlers)
assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in _OPENER.handlers)
'''
        with self.serving(FakeNod) as (port, nod), self.serving(ProxyTrap) as (proxy_port, proxy):
            proxy_url = f'http://127.0.0.1:{proxy_port}'
            result = subprocess.run(
                [sys.executable, '-c', probe, f'http://127.0.0.1:{port}/nod/', proxy_url],
                cwd=Path(__file__).resolve().parents[2],
                env={'HTTP_PROXY': proxy_url, 'HTTPS_PROXY': proxy_url, 'NO_PROXY': '',
                     'PYTHONDONTWRITEBYTECODE': '1'},
                capture_output=True, text=True, timeout=10)
            self.assertEqual(proxy.received, [])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(nod.received, [
                ('/nod/api/v1/requests', 'Bearer fake-issuer-only'),
                ('/nod/api/v1/requests/nod-123/decision', 'Bearer fake-issuer-only'),
                ('/nod/api/v1/requests/nod-123/cancel', 'Bearer fake-issuer-only')])
            self.assertEqual(nod.created['body']['title'], CARD.title)
            self.assertEqual(nod.created['auth'], 'Bearer fake-issuer-only')


if __name__ == "__main__":
    unittest.main()
