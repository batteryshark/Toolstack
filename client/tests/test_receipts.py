import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from client import toolstack, mcp_server


class Receipts(unittest.TestCase):
    def test_lost_response_reports_unknown_with_original_key_without_retry(self):
        with patch.object(toolstack, "_send", side_effect=TimeoutError("fake-sensitive")) as send:
            status, out = toolstack._request("POST", "/v1/actions/echo.say", {}, idempotency_key="same-key")
        self.assertEqual((status, out["status"], out["idempotency_key"]), (502, "unknown", "same-key"))
        self.assertNotIn("fake-sensitive", str(out))
        self.assertEqual(send.call_count, 1)

    def test_cli_key_is_request_metadata(self):
        args = argparse.Namespace(spec="echo.say", args='{"a":1}', args_file=None,
                                  reason=None, wait=False, timeout=1, idempotency_key="same-key")
        with patch.object(toolstack, "_request", return_value=(200, {"status": "ok", "request_id": 7})) as send, redirect_stdout(io.StringIO()):
            toolstack.cmd_call(args)
        send.assert_called_once_with("POST", "/v1/actions/echo.say", {"arguments": {"a": 1}}, idempotency_key="same-key")

    def test_received_executing_wait_but_unknown_never_loops(self):
        with patch.object(toolstack, "_request", return_value=(200, {"status": "executing", "request_id": 7})), redirect_stdout(io.StringIO()):
            timed = toolstack._poll_until_done(7, 0)
            self.assertEqual((timed["status"], timed["broker_status"]), ("timeout", "executing"))
        with patch.object(toolstack, "_request", return_value=(200, {"status": "unknown", "request_id": 7})) as read:
            self.assertEqual(toolstack._poll_until_done(7, 1)["status"], "unknown")
            read.assert_called_once()
        for status in ("received", "executing", "unknown", "result_expired", "conflict"):
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                toolstack._finish({"status": status, "request_id": 7})

    def test_mcp_received_wait_is_bounded_and_truthful(self):
        server = mcp_server.Server(poll_timeout=0)
        with patch.object(mcp_server, "_call", return_value=(202, {"status": "received", "request_id": 7})):
            out = server._poll(7)
        self.assertEqual((out["status"], out["broker_status"]), ("timeout", "received"))

    def test_invalid_key_is_refused_before_transport(self):
        with patch.object(toolstack._OPENER, "open") as opened:
            for key in ("", "bad key", "a:b", "*", "x"*129, "a\r\nb"):
                with self.assertRaises(ValueError):
                    toolstack._send("POST", "/test", {}, idempotency_key=key)
            opened.assert_not_called()
