"""Finite, owned HTTP/fake-socket regressions for input and output phases."""
import http.client
import io
import json
import threading
import unittest
from http.server import HTTPServer
from types import SimpleNamespace
from unittest.mock import Mock, patch

from broker.server import _Handler


class FakeSocket:
    def __init__(self, request, fail_write=None, error=TimeoutError):
        self.input = io.BytesIO(request)
        self.output = bytearray()
        self.fail_write = fail_write
        self.error = error
        self.writes = 0
        self.timeouts = []

    def makefile(self, *args):
        return io.BytesIO()

    def recv_into(self, buffer):
        return self.input.readinto(buffer)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.writes += 1
        if self.writes == self.fail_write:
            self.output.extend(data[:16])
            raise self.error("private-output-error")
        self.output.extend(data)


class TransportSecurity(unittest.TestCase):
    def test_deep_json_is_sanitized_and_serial_listener_recovers(self):
        audit = Mock()
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        server.ctx = SimpleNamespace(audit=audit)
        worker = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            with patch("broker.server.handle") as dispatch, patch.object(server, "handle_error") as errors:
                for body in (b"[" * 2000, b"[" * 2000 + b"0" + b"]" * 2000):
                    with self.subTest(body_length=len(body)):
                        conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                        try:
                            conn.request("POST", "/v1/requests", body=body)
                            response = conn.getresponse()
                            self.assertEqual(response.status, 400)
                            self.assertEqual(json.loads(response.read()), {"error": "invalid_request"})
                            correlation = response.getheader("X-Correlation-Id")
                            audit.record.assert_called_with("gateway", "transport_error", "invalid",
                                                            correlation, details={"status": 400})
                        finally:
                            conn.close()
                dispatch.assert_not_called()
                errors.assert_not_called()
                dispatch.return_value = SimpleNamespace(status=200, body={"ok": True}, correlation_id="recovery")
                conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                try:
                    conn.request("GET", "/v1/health")
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {"ok": True})
                finally:
                    conn.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(server.socket.fileno(), -1)

    def test_partial_response_failure_never_sends_second_status_or_invalidates_action(self):
        for fail_write in (1, 2):
            for error in (TimeoutError, BrokenPipeError):
                with self.subTest(fail_write=fail_write, error=error):
                    audit = Mock()
                    sock = FakeSocket(b"POST /v1/actions/fake.send HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}",
                                      fail_write, error)
                    def completed(*args):
                        audit.record("execution", "completed", "ok", "test-action", details={"status": 200})
                        return SimpleNamespace(status=200, body={"ok": True}, correlation_id="test-action")
                    with patch("broker.server.handle", side_effect=completed) as dispatch:
                        _Handler(sock, ("127.0.0.1", 1), SimpleNamespace(ctx=SimpleNamespace(audit=audit)))
                    dispatch.assert_called_once()
                    self.assertEqual(sock.writes, fail_write)
                    self.assertEqual(sock.output.count(b"HTTP/1.0"), 1)
                    self.assertNotIn(b"408", sock.output)
                    self.assertEqual(audit.record.call_count, 2)
                    audit.record.assert_called_with("gateway", "output_error", "failed", "test-action",
                                                    details={"status": 200})
                    self.assertNotIn("private-output-error", str(audit.record.call_args_list))

    def test_output_budget_replaces_input_timeout_and_spans_both_writes(self):
        for header_duration in (0.4, 0.6):
            with self.subTest(header_duration=header_duration):
                clock = [0.0]
                audit = Mock()
                sock = FakeSocket(b"GET /v1/health HTTP/1.0\r\n\r\n")
                sendall = sock.sendall
                def timed_send(data):
                    sendall(data)
                    clock[0] += header_duration
                sock.sendall = timed_send
                response = SimpleNamespace(status=200, body={"ok": True}, correlation_id="budget")
                with patch("broker.server.time.monotonic", side_effect=lambda: clock[0]), \
                     patch("broker.server.INPUT_TOTAL_SECONDS", 0.01), \
                     patch("broker.server.OUTPUT_TOTAL_SECONDS", 0.5), \
                     patch("broker.server.OUTPUT_WRITE_SECONDS", 0.3), \
                     patch("broker.server.handle", return_value=response):
                    _Handler(sock, ("127.0.0.1", 1), SimpleNamespace(ctx=SimpleNamespace(audit=audit)))
                self.assertEqual(sock.timeouts[:2], [0.01, 0.3])
                if header_duration < 0.5:
                    self.assertEqual(sock.writes, 2)
                    self.assertAlmostEqual(sock.timeouts[-1], 0.1)
                    audit.record.assert_not_called()
                else:
                    self.assertEqual(sock.writes, 1)
                    audit.record.assert_called_once_with("gateway", "output_error", "failed", "budget",
                                                         details={"status": 200})

    def test_refusal_output_failure_is_sanitized_without_second_response(self):
        for status, request in (
            (400, b"POST /v1/requests HTTP/1.0\r\nContent-Length: -1\r\n\r\n"),
            (413, b"POST /v1/requests HTTP/1.0\r\nContent-Length: 999999\r\n\r\n"),
            (500, b"GET /v1/health HTTP/1.0\r\n\r\n"),
        ):
            for fail_write in (1, 2):
                with self.subTest(status=status, fail_write=fail_write):
                    audit = Mock()
                    sock = FakeSocket(request, fail_write)
                    with patch("broker.server.handle", side_effect=RuntimeError("private-action-error")) as dispatch:
                        _Handler(sock, ("127.0.0.1", 1), SimpleNamespace(ctx=SimpleNamespace(audit=audit)))
                    self.assertEqual(dispatch.call_count, int(status == 500))
                    self.assertEqual(sock.writes, fail_write)
                    self.assertEqual(sock.output.count(b"HTTP/1.0"), 1)
                    self.assertEqual(audit.record.call_count, 2)
                    first, last = audit.record.call_args_list
                    self.assertEqual(first.args[:3], ("gateway", "transport_error",
                                                      "failed" if status == 500 else "invalid"))
                    self.assertEqual(last.args[:3], ("gateway", "output_error", "failed"))
                    self.assertEqual(first.args[3], last.args[3])
                    self.assertEqual(first.kwargs, {"details": {"status": status}})
                    self.assertEqual(last.kwargs, first.kwargs)
                    self.assertNotIn("private-", str(audit.record.call_args_list))
                    self.assertNotIn(b"private-", sock.output)


if __name__ == "__main__":
    unittest.main()
