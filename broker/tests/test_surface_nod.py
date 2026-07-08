"""NodSurface HTTP adapter: maps an OperationCard to nod's create request (issuer
token, no raw args, redacted push) and maps nod's decision back to a SurfaceState.

The fake below is wire-faithful to nod v1.0.1 (nod-proto @ 01d535d): it enforces
the real create-body contract (`deny_unknown_fields`, required `title`) and
returns the real response shapes. So if the adapter starts sending a field nod
would reject, or stops reading one nod actually returns, these tests fail.
For a check against a *real* nod server, see test_surface_nod_live.py."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from broker import approval
from broker.approval import OperationCard
from broker.surface_nod import NodSurface

CARD = OperationCard(
    request_id=7, title="Approve echo.shout for caller hermes",
    caller="hermes", tool="echo", op="shout", risk="destructive", reason="policy review",
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
            "decision": {"request_id": "nod-123", "option_id": option_kind,
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
        self.assertEqual(body["dedupe_key"], "7")  # retry-safe
        self.assertEqual(body["title"], CARD.title)
        self.assertTrue(body["notification"]["redact"])
        self.assertNotIn("arguments", body)  # no raw args in the card

    def test_open_includes_redacted_request_in_body_markdown(self):
        card = OperationCard(
            request_id=7, title="Approve echo.shout for caller hermes", caller="hermes",
            tool="echo", op="shout", risk="write", reason="policy review",
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

    def test_poll_pending(self):
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.PENDING)

    def test_poll_approved(self):
        _FakeNod.decision = _resolved_view("approve")
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.APPROVED)
        self.assertEqual(state.approver, "owner")
        self.assertEqual(state.decided_at, "2026-06-17T00:00:00.000Z")  # nod resolved_at

    def test_poll_approved_with_text(self):
        _FakeNod.decision = _resolved_view("approve_with_text", text="lgtm")
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.APPROVED)
        self.assertEqual(state.note, "lgtm")

    def test_poll_rejected(self):
        _FakeNod.decision = _resolved_view("reject_with_text", text="nope")
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.REJECTED)
        self.assertEqual(state.note, "nope")

    def test_poll_dismiss_is_not_an_approval(self):
        _FakeNod.decision = _resolved_view("dismiss")
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.PENDING)

    def test_poll_expired(self):
        _FakeNod.decision = {"status": "expired", "decision": None}
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.EXPIRED)

    def test_poll_cancelled(self):
        _FakeNod.decision = {"status": "cancelled", "decision": None}
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.CANCELLED)

    def test_cancel_is_best_effort(self):
        # Returns None and does not raise, even though nod replies with a body.
        self.assertIsNone(self.surface.cancel("nod-123"))


if __name__ == "__main__":
    unittest.main()
