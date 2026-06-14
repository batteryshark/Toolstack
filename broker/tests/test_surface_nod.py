"""NodSurface HTTP adapter: maps an OperationCard to nod's create request (issuer
token, no raw args, redacted push) and maps nod's decision back to a SurfaceState."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from broker import approval
from broker.approval import OperationCard
from broker.surface_nod import NodSurface

CARD = OperationCard(
    request_id=7, title="Approve echo.shout for caller hermes",
    caller="hermes", tool="echo", op="shout", risk="high", reason="policy review",
)


class _FakeNod(BaseHTTPRequestHandler):
    created = None
    decision = None  # None = pending; else the decision-read body

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        if self.path == "/api/v1/requests":
            type(self).created = {"auth": self.headers.get("Authorization"), "body": body}
            return self._send(200, {"request_id": "nod-123", "deduped": False})
        if self.path.endswith("/cancel"):
            return self._send(200, {})
        return self._send(404, {"error": "nf"})

    def do_GET(self):
        if self.path == "/api/v1/requests/nod-123/decision":
            body = type(self).decision or {"status": "pending", "decision": None}
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


class NodSurfaceHTTP(unittest.TestCase):
    def setUp(self):
        _FakeNod.created = None
        _FakeNod.decision = None
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
        self.assertEqual(_FakeNod.created["auth"], "Bearer issuer-tok")
        body = _FakeNod.created["body"]
        self.assertEqual(body["dedupe_key"], "7")  # retry-safe
        self.assertEqual(body["title"], CARD.title)
        self.assertTrue(body["notification"]["redact"])
        self.assertNotIn("arguments", body)  # no raw args in the card

    def test_poll_pending(self):
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.PENDING)

    def test_poll_approved(self):
        _FakeNod.decision = {"status": "resolved",
                             "decision": {"option_kind": "approve", "actor_user_id": "owner", "text": None}}
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.APPROVED)
        self.assertEqual(state.approver, "owner")

    def test_poll_rejected(self):
        _FakeNod.decision = {"status": "resolved",
                             "decision": {"option_kind": "reject_with_text", "actor_user_id": "owner", "text": "nope"}}
        state = self.surface.poll("nod-123")
        self.assertEqual(state.outcome, approval.REJECTED)
        self.assertEqual(state.note, "nope")

    def test_poll_expired(self):
        _FakeNod.decision = {"status": "expired", "decision": None}
        self.assertEqual(self.surface.poll("nod-123").outcome, approval.EXPIRED)


if __name__ == "__main__":
    unittest.main()
