"""Client end-to-end: drive the `toolstack` CLI against a real broker (with a fake
runtime + fake approval surface), covering discovery, allowed calls, and the
review → wait → approver-note round-trip."""

import argparse
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

from broker import approval
from broker.identity import hash_token
from broker.server import build_server
from broker.tests.support import FakeRuntime, FakeSurface, make_registry
from client import toolstack


class ClientIntegration(unittest.TestCase):
    def setUp(self):
        self.surface = FakeSurface(approval.PENDING)
        self.server = build_server(
            port=0, db_path=":memory:", audit_sink=None, rate_limit=0,
            registry=make_registry({"echo": {"say": "low", "skip": "high"}}),
            runtime=FakeRuntime(), surface=self.surface,
        )
        self.port = self.server.server_address[1]
        store = self.server.ctx.store
        caller_id = store.add_caller("hermes")
        store.add_token(caller_id, hash_token("t"))
        store.set_policy(caller_id, {"tools": {"echo": {"say": "allow", "skip": "review"}}})
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        os.environ["TOOLSTACK_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ["TOOLSTACK_TOKEN"] = "t"
        self.addCleanup(os.environ.pop, "TOOLSTACK_URL", None)
        self.addCleanup(os.environ.pop, "TOOLSTACK_TOKEN", None)

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.server.ctx.store.close()

    def _out(self, func, **kw):
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                func(argparse.Namespace(**kw))
        except SystemExit:
            pass
        return buf.getvalue()

    def test_tools_lists_allowed_with_effects(self):
        out = self._out(toolstack.cmd_tools)
        self.assertIn("echo.say", out)
        self.assertIn("echo.skip", out)
        self.assertIn("allow", out)
        self.assertIn("review", out)

    def test_describe(self):
        out = self._out(toolstack.cmd_describe, spec="echo.say")
        self.assertIn('"op": "say"', out)

    def test_whoami(self):
        self.assertIn("hermes", self._out(toolstack.cmd_whoami))

    def test_call_allowed_runs(self):
        out = self._out(toolstack.cmd_call, spec="echo.say", args='{"m": "hi"}',
                        args_file=None, reason=None, wait=False, timeout=5)
        self.assertIn('"status": "ok"', out)
        self.assertIn("echoed", out)

    def test_call_via_stdin_handles_tricky_data(self):
        tricky = "it's \"messy\"\nmulti-line $data"
        original_stdin = toolstack.sys.stdin
        toolstack.sys.stdin = io.StringIO(json.dumps({"m": tricky}))
        self.addCleanup(setattr, toolstack.sys, "stdin", original_stdin)
        out = self._out(toolstack.cmd_call, spec="echo.say", args=None,
                        args_file=None, reason=None, wait=False, timeout=5)
        self.assertIn('"status": "ok"', out)
        self.assertIn("multi-line", out)

    def test_call_via_args_file(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"m": "from a file with 'quotes'"}))
        out = self._out(toolstack.cmd_call, spec="echo.say", args=None,
                        args_file=path, reason=None, wait=False, timeout=5)
        self.assertIn('"status": "ok"', out)
        self.assertIn("from a file", out)

    def test_review_wait_approved_surfaces_note(self):
        self.surface.set(approval.APPROVED, approver="alice", note="ok by me")
        out = self._out(toolstack.cmd_call, spec="echo.skip", args="{}",
                        args_file=None, reason="please skip", wait=True, timeout=5)
        self.assertIn('"status": "ok"', out)
        self.assertIn("alice", out)
        self.assertIn("ok by me", out)  # the approver's note reaches the agent

    def test_review_wait_rejected_surfaces_note(self):
        self.surface.set(approval.REJECTED, approver="alice", note="not now")
        out = self._out(toolstack.cmd_call, spec="echo.skip", args="{}",
                        args_file=None, reason=None, wait=True, timeout=5)
        self.assertIn('"status": "denied"', out)
        self.assertIn("not now", out)


if __name__ == "__main__":
    unittest.main()
