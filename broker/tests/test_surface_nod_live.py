"""Live nod integration test: opt-in, skipped by default.

Unlike test_surface_nod.py (which runs against a wire-faithful fake), this drives
a REAL nod server through a full open -> poll -> cancel -> poll cycle, to pin the
contract against a live deployment and catch drift the fake can't (auth scopes,
routing, real status transitions).

It is skipped unless BOTH env vars are set:

    TOOLSTACK_NOD_URL     base URL incl. any path prefix, e.g.
                          https://host.example.ts.net/boop
    TOOLSTACK_NOD_TOKEN   issuer token. Needs requests:write, requests:read AND
                          requests:cancel (or simply requests:*). nod's DEFAULT
                          issuer token is write+read only, and nod has no
                          write→cancel fallback (auth.rs has_request_scope), so a
                          write+read token gets 403 on cancel and this test would
                          leave a dangling pending request. Mint the token with
                          cancel scope, e.g. scopes ["requests:*"].

Optional:
    TOOLSTACK_NOD_CHANNEL channel id (default "default")

⚠️  Side effect: opening a request notifies the issuer's enrolled nod devices.
The test immediately cancels the request it creates, so nothing stays pending,
but a card may briefly appear. If cleanup can't cancel (wrong scope), the test
prints a loud warning naming the request id so you can dismiss it by hand. Run
it knowingly:

    TOOLSTACK_NOD_URL=https://host/boop TOOLSTACK_NOD_TOKEN=... \\
        python3 -m unittest broker.tests.test_surface_nod_live -v
"""

import os
import sys
import time
import unittest

from broker import approval
from broker.approval import build_card
from broker.surface_nod import NodSurface

_URL = os.environ.get("TOOLSTACK_NOD_URL")
_TOKEN = os.environ.get("TOOLSTACK_NOD_TOKEN")
_CHANNEL = os.environ.get("TOOLSTACK_NOD_CHANNEL", "default")


@unittest.skipUnless(
    _URL and _TOKEN,
    "set TOOLSTACK_NOD_URL and TOOLSTACK_NOD_TOKEN to run the live nod test",
)
class NodSurfaceLive(unittest.TestCase):
    def setUp(self):
        self.surface = NodSurface(_URL, _TOKEN, channel=_CHANNEL)
        # Unique per run so a rerun doesn't dedupe onto a prior run's request.
        self.card = build_card(
            request_id=int(time.time()),
            caller="tsr-selftest", tool="echo", op="ping", risk="read",
            reason="surface_nod live contract test",
            justification="automated open->poll->cancel cycle; safe to reject",
        )
        self.ref = None

    def tearDown(self):
        # Always clean up, even if an assertion failed mid-cycle. cancel() is
        # best-effort and swallows errors (e.g. a 403 from a token lacking the
        # requests:cancel scope), so confirm the cancel actually took and warn
        # loudly if a real request is still pending on the live server.
        if not self.ref:
            return
        self.surface.cancel(self.ref)
        try:
            leftover = self.surface.poll(self.ref).outcome
        except Exception:
            return  # can't confirm; nothing more to do
        if leftover not in (approval.CANCELLED, approval.EXPIRED):
            sys.stderr.write(
                f"\n⚠️  live nod request {self.ref} is still {leftover!r} after "
                "cancel. Your issuer token likely lacks the requests:cancel "
                "scope. Dismiss it by hand and re-run with a requests:* token.\n"
            )

    def test_open_poll_cancel_cycle(self):
        # open -> a request id we can poll.
        self.ref = self.surface.open(self.card)
        self.assertTrue(self.ref, "open() must return a non-empty request id")

        # poll before anyone decides -> pending.
        state = self.surface.poll(self.ref)
        self.assertEqual(
            state.outcome, approval.PENDING,
            f"fresh request should poll PENDING, got {state.outcome}",
        )

        # cancel -> best effort, returns None and must not raise.
        self.assertIsNone(self.surface.cancel(self.ref))

        # poll after cancel -> CANCELLED (allow brief eventual consistency).
        outcome = None
        for _ in range(5):
            outcome = self.surface.poll(self.ref).outcome
            if outcome == approval.CANCELLED:
                break
            time.sleep(0.5)
        self.assertEqual(
            outcome, approval.CANCELLED,
            f"cancelled request should poll CANCELLED, got {outcome}",
        )
        self.ref = None  # already cancelled; skip redundant tearDown cancel


if __name__ == "__main__":
    unittest.main()
