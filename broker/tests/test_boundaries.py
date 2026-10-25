"""Synthetic two-connection state and transport regression checks."""
import concurrent.futures
import sqlite3
import tempfile
import threading
import unittest
import json
import http.client
import socket
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from pathlib import Path

from broker import approval, request_lifecycle as lifecycle
from broker.identity import authenticate
from broker.audit import AuditLog
from broker.store import Store, SCHEMA
from broker.runtime import HttpRuntime
from broker.registry import ToolOp
from broker.bounds import operation_bounds, LimitExceeded
from broker.server import build_server
from broker.gateway import make_correlation_id
from broker.gateway import handle
from .support import make_ctx, seed_caller


class Persistence(unittest.TestCase):
    def test_failed_migration_rolls_back_all_ddl(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.db")
            with patch("broker.store.SCHEMA", SCHEMA + "CREATE TABLE broken("), self.assertRaises(sqlite3.Error):
                Store(path)
            conn = sqlite3.connect(path)
            try:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT name FROM sqlite_master").fetchall(), [])
            finally:
                conn.close()

    def test_legacy_migration_serializes_two_openers(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.db")
            conn = sqlite3.connect(path)
            conn.executescript(SCHEMA)
            conn.execute("INSERT INTO callers VALUES (1,'legacy',0,NULL)")
            conn.execute("INSERT INTO tokens VALUES ('fake-hash',1,0,NULL)")
            conn.execute("INSERT INTO requests VALUES (1,'legacy',1,'echo','say','pending_approval','{}',NULL,NULL,0,0)")
            conn.execute("INSERT INTO approvals VALUES (1,1,'fake-ref','pending',99999999999,NULL,NULL,NULL,0)")
            conn.commit()
            conn.close()
            barrier = threading.Barrier(2)
            def open_store():
                barrier.wait(timeout=5)
                store = Store(path)
                try:
                    return store.caller_name(1), store._conn.execute("PRAGMA user_version").fetchone()[0]
                finally:
                    store.close()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(open_store) for _ in range(2)]
                self.assertEqual([f.result(timeout=10) for f in futures], [("legacy", 3)] * 2)
            store = Store(path)
            try:
                self.assertFalse(store.claim_approval(1, "new-generation", approval.SurfaceState(approval.APPROVED), 1))
                self.assertEqual(store.request(1)["error"], "approval_invalidated")
            finally:
                store.close()

    def test_newer_schema_refused_without_schema_changes(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "broker.db")
            conn = sqlite3.connect(path)
            conn.execute("PRAGMA user_version=99")
            conn.close()
            with self.assertRaisesRegex(ValueError, "newer"):
                Store(path)
            conn = sqlite3.connect(path)
            try:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 99)
                self.assertEqual(conn.execute("SELECT name FROM sqlite_master").fetchall(), [])
            finally:
                conn.close()

    def test_existing_public_parent_refused_not_chmodded(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d) / "shared"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)  # fixture must remain unsafe even under umask077
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            with self.assertRaisesRegex(ValueError, "private directory"):
                Store(str(parent / "broker.db"))
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertFalse((parent / "broker.db").exists())

    def test_private_parent_under_writable_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as d:
            shared = Path(d) / "shared"
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            private = shared / "private"
            private.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "unsafe writable ancestor"):
                Store(str(private / "broker.db"))
            self.assertEqual(shared.stat().st_mode & 0o777, 0o777)

    def test_late_terminal_polls_preserve_second_connection_cancellation(self):
        for decision in (approval.APPROVED, approval.REJECTED, approval.CANCELLED,
                         approval.EXPIRED, approval.PENDING):
            with self.subTest(decision=decision), tempfile.TemporaryDirectory() as d:
                ctx = make_ctx(catalog={"echo": {"say": "low"}})
                ctx.store.close()

                path = str(Path(d) / "broker.db")
                ctx.store = Store(path)
                ctx.audit = AuditLog(ctx.store, sink=None)
                other = Store(path)
                try:
                    token = seed_caller(ctx.store, review=["echo.say"])
                    caller = authenticate(ctx.store, f"Bearer {token}")
                    out = lifecycle.submit(ctx, caller, "echo", "say", {}, "race")
                    def poll(ref):
                        self.assertTrue(other.finish_pending(out.request_id, "expired", "cancelled"))
                        return approval.SurfaceState(decision)
                    ctx.surface.poll = poll
                    result = lifecycle.resolve_request(ctx, out.request_id)
                    self.assertEqual(result.status, lifecycle.EXPIRED)
                    self.assertEqual(ctx.store.approval_for_request(out.request_id)["status"], "cancelled")
                    self.assertEqual(ctx.runtime.calls, [])
                finally:
                    other.close()
                    ctx.store.close()


@contextmanager
def serving(server):
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


class Transport(unittest.TestCase):
    def test_denied_rest_skips_operation_specific_validation(self):
        ctx = make_ctx(catalog={"fake": {"send": "write"}}, tool_type="rest", rest_meta={"body_kind": "binary"})
        try:
            token = seed_caller(ctx.store)
            body = {"arguments": {"body": "not base64!"}}
            response = handle("POST", "/v1/actions/fake.send", {"Authorization": f"Bearer {token}"}, body, ctx)
            self.assertEqual(response.status, 403)
            self.assertNotIn("base64", json.dumps(response.body))
        finally:
            ctx.store.close()

    def test_header_cap_and_unexpected_error_are_sanitized(self):
        server = build_server(port=0, db_path=":memory:", audit_sink=None)
        try:
            with serving(server) as port:
                with patch("broker.server.MAX_HEADER_BYTES", 128):
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                        sock.sendall(b"GET /v1/health HTTP/1.0\r\nX: " + b"x" * 256 + b"\r\n\r\n")
                        self.assertIn(b"431", sock.makefile("rb").read().split(b"\r\n")[0])
                with patch("broker.server.handle", side_effect=RuntimeError("fake-sensitive-value")):
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                        sock.sendall(b"GET /v1/health HTTP/1.0\r\n\r\n")
                        response = http.client.HTTPResponse(sock)
                        response.begin()
                        self.assertEqual(response.status, 500)
                        self.assertNotIn(b"fake-sensitive-value", response.read())
                        correlation = response.getheader("X-Correlation-Id")
                        response.close()
                        event = server.ctx.store.audit_events()[-1]
                        self.assertEqual(event["correlation_id"], correlation)
                        self.assertEqual(event["details"], {"status": 500})
        finally:
            server.ctx.store.close()

    def test_slow_body_and_body_size_cap(self):
        with patch("broker.server.INPUT_TOTAL_SECONDS", 0.15), patch("broker.server.INPUT_IDLE_SECONDS", 0.08):
            server = build_server(port=0, db_path=":memory:", audit_sink=None)
            try:
                with serving(server) as port:
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                        sock.sendall(b"POST /v1/actions/x.y HTTP/1.0\r\nContent-Length: 100\r\n\r\n{")
                        response = sock.makefile("rb").read()
                        self.assertIn(b"408", response.split(b"\r\n")[0])
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                        sock.sendall(b"POST /mcp HTTP/1.0\r\nContent-Length: 99999999\r\n\r\n")
                        self.assertIn(b"413", sock.makefile("rb").read().split(b"\r\n")[0])
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                        sock.sendall(b"GET /v1/health HTTP/1.0\r\n\r\n")
                        self.assertIn(b"200", sock.makefile("rb").read().split(b"\r\n")[0])
            finally:
                server.ctx.store.close()

    def test_jsonrpc_response_id_mismatch_is_refused(self):
        class WrongID(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"jsonrpc":"2.0","id":999,"result":{}}')
            def log_message(self, *args):
                pass
        with serving(HTTPServer(("127.0.0.1", 0), WrongID)) as port:
            with operation_bounds(1, 4096), self.assertRaisesRegex(RuntimeError, "mismatched"):
                HttpRuntime()._mcp_request(f"http://127.0.0.1:{port}/mcp", None, None, None, 2, "tools/call", {})

    def test_second_connection_revocation_during_rejected_poll_wins(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(catalog={"echo": {"say": "low"}})
            ctx.store.close()
            ctx.store = Store(str(Path(d) / "broker.db"))
            ctx.audit = AuditLog(ctx.store, sink=None)
            other = Store(str(Path(d) / "broker.db"))
            try:
                token = seed_caller(ctx.store, review=["echo.say"])
                caller = authenticate(ctx.store, f"Bearer {token}")
                out = lifecycle.submit(ctx, caller, "echo", "say", {}, "race")
                def poll(ref):
                    other.revoke_caller("hermes")
                    return approval.SurfaceState(approval.REJECTED)
                ctx.surface.poll = poll
                result = lifecycle.resolve_request(ctx, out.request_id)
                self.assertEqual(result.status, lifecycle.EXPIRED)
                self.assertEqual(ctx.store.approval_for_request(out.request_id)["status"], "cancelled")
                self.assertEqual(ctx.runtime.calls, [])
            finally:
                other.close()
                ctx.store.close()

    def test_bad_framing_has_stable_json_and_releases_serial_broker(self):
        server = build_server(port=0, db_path=":memory:", audit_sink=None)
        try:
            with serving(server) as port:
                for framing in (b"Content-Length: -1\r\n", b"Content-Length: x\r\n",
                                b"Content-Length: 0\r\nContent-Length: 0\r\n",
                                b"Transfer-Encoding: chunked\r\n",
                                b"Idempotency-Key: first\r\nIdempotency-Key: second\r\n"):
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                        sock.sendall(b"POST /v1/actions/x.y HTTP/1.0\r\n" + framing + b"\r\n")
                        response = sock.makefile("rb").read()
                        self.assertIn(b"400", response.split(b"\r\n")[0])
                        self.assertTrue(response.endswith(b'{"error": "invalid_request"}'))
        finally:
            server.ctx.store.close()

    def test_absolute_slow_header_deadline_and_idle_deadline(self):
        with patch("broker.server.INPUT_TOTAL_SECONDS", 0.15), patch("broker.server.INPUT_IDLE_SECONDS", 0.08):
            server = build_server(port=0, db_path=":memory:", audit_sink=None)
            try:
                with serving(server) as port:
                    for drip in (False, True):
                        start = time.monotonic()
                        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                            sock.sendall(b"GET /v1/health HTTP/1.0\r\nX: ")
                            if drip:
                                for _ in range(4):
                                    time.sleep(0.03)
                                    try:
                                        sock.sendall(b"a")
                                    except OSError:
                                        break
                            response = http.client.HTTPResponse(sock)
                            response.begin()
                            self.assertEqual(response.status, 408)
                            self.assertEqual(json.loads(response.read()), {"error": "request_timeout"})
                            response.close()
                            self.assertLess(time.monotonic() - start, 0.8)
            finally:
                server.ctx.store.close()

    def test_correlation_id_alphabet(self):
        for value in ("hello world", "a:b", "a\r\nb", "x" * 65, "é"):
            self.assertRegex(make_correlation_id({"x-correlation-id": value}), r"^[0-9a-f]{32}$")
        self.assertEqual(make_correlation_id({"x-correlation-id": "safe_1-ID"}), "safe_1-ID")

    def test_runtime_total_deadline_includes_trickled_headers_and_body(self):
        for phase in ("headers", "body"):
            class Slow(BaseHTTPRequestHandler):
                def do_POST(self):
                    self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    try:
                        if phase == "headers":
                            self.connection.sendall(b"HTTP/1.0 200 OK\r\nX: ")
                        else:
                            self.send_response(200)
                            self.end_headers()
                        for _ in range(15):
                            self.connection.sendall(b" ")
                            time.sleep(0.02)
                    except OSError:
                        pass
                def log_message(self, *args):
                    pass
            with serving(HTTPServer(("127.0.0.1", 0), Slow)) as port:
                runtime = HttpRuntime(timeout=0.12, tool_secret=lambda _: None)
                start = time.monotonic()
                with self.assertRaises((TimeoutError, RuntimeError)):
                    runtime.execute(ToolOp("fake", "say", "read", port, "api"), {}, 1, "test")
                self.assertLess(time.monotonic() - start, 0.5)

    def test_runtime_response_cap(self):
        class Large(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * 1024)
            def log_message(self, *args):
                pass
        with serving(HTTPServer(("127.0.0.1", 0), Large)) as port:
            runtime = HttpRuntime(tool_secret=lambda _: None)
            runtime._response_max = 64
            with self.assertRaises(LimitExceeded):
                runtime.execute(ToolOp("fake", "say", "read", port, "api"), {}, 1, "test")

    def test_incremental_sse_matches_id_without_waiting_for_close(self):
        class SSE(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for mid in (999, 2):
                    msg = {"jsonrpc": "2.0", "id": mid, "result": {"isError": True}}
                    self.wfile.write(b"data: " + json.dumps(msg).encode() + b"\n\n")
                self.wfile.flush()
                time.sleep(0.25)
            def log_message(self, *args):
                pass
        with serving(HTTPServer(("127.0.0.1", 0), SSE)) as port:
            runtime = HttpRuntime()
            start = time.monotonic()
            with operation_bounds(0.15, 4096):
                result, _ = runtime._mcp_request(f"http://127.0.0.1:{port}/mcp", None, None, None, 2, "tools/call", {})
            self.assertTrue(result["isError"])
            self.assertLess(time.monotonic() - start, 0.15)

    def test_stale_sweep_cannot_expire_claimed_execution(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(catalog={"echo": {"say": "low"}})
            ctx.store.close()
            path = str(Path(d) / "broker.db")
            ctx.store = Store(path)
            ctx.audit = AuditLog(ctx.store, sink=None)
            other = Store(path)
            try:
                token = seed_caller(ctx.store, review=["echo.say"])
                caller = authenticate(ctx.store, f"Bearer {token}")
                out = lifecycle.submit(ctx, caller, "echo", "say", {}, "race")
                op = ctx.registry.lookup("echo", "say")
                self.assertTrue(other.claim_approval(out.request_id, op.generation,
                                                    approval.SurfaceState(approval.APPROVED), 1))
                self.assertFalse(ctx.store.finish_pending(out.request_id, "expired", "expired", now=1e12))
                self.assertEqual(ctx.store.request(out.request_id)["status"], "executing")
            finally:
                other.close()
                ctx.store.close()
