"""Egress proxy: it forwards a request to a host on the allowlist and refuses (403) any
other host, for both plain HTTP and CONNECT tunnels. Exercised against local servers, so it
is deterministic and needs no external network.
"""

import socket
import threading
import time
import unittest
from unittest.mock import patch, Mock
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from toolyard.egress_proxy import serve
from toolyard import egress_proxy


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Origin(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path in ("/slow-header", "/slow-body"):
            try:
                if self.path == "/slow-body":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                for _ in range(50):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.04)  # well below the five-second idle limit
            except OSError:
                pass
            return
        body = b"origin-body"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EgressProxyTest(unittest.TestCase):
    def setUp(self):
        # An HTTP origin and a raw-TCP echo server, both on loopback; the proxy allows only
        # 127.0.0.1, so both are reachable and any other host is refused.
        self.origin = ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        self.origin.daemon_threads = False
        origin_thread = threading.Thread(target=self.origin.serve_forever)
        origin_thread.start()
        self.addCleanup(self.origin.server_close)
        self.addCleanup(self._stop_server, self.origin, origin_thread)
        self.origin_port = self.origin.server_address[1]

        self.echo = socket.socket()
        self.echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.echo.bind(("127.0.0.1", 0))
        self.echo.listen(1)
        self.echo_port = self.echo.getsockname()[1]
        self.echo.settimeout(0.1)
        self.echo_stop = threading.Event()
        self.echo_workers = []
        echo_thread = threading.Thread(target=self._echo_serve)
        echo_thread.start()
        self.addCleanup(self._stop_echo, echo_thread)

        self.proxy = serve(_free_port(), ["127.0.0.1", f"127.0.0.1:{self.echo_port}"])
        self.proxy.daemon_threads = False
        proxy_thread = threading.Thread(target=self.proxy.serve_forever)
        proxy_thread.start()
        self.addCleanup(self.proxy.server_close)
        self.addCleanup(self._stop_server, self.proxy, proxy_thread)
        self.proxy_port = self.proxy.server_address[1]

    def _echo_serve(self):
        while not self.echo_stop.is_set():
            try:
                conn, _ = self.echo.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(2)
            def echo(c=conn):
                with c:
                    try:
                        c.sendall(c.recv(64))
                    except OSError:
                        pass
            worker = threading.Thread(target=echo)
            self.echo_workers.append(worker)
            worker.start()

    def _stop_echo(self, thread):
        self.echo_stop.set()
        self.echo.close()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        for worker in self.echo_workers:
            worker.join(3)
            self.assertFalse(worker.is_alive())

    def _stop_server(self, server, thread):
        server.shutdown()
        thread.join(3)
        self.assertFalse(thread.is_alive())

    def _raw(self, headers="", path="/"):
        client = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=2)
        self.addCleanup(client.close)
        client.sendall((f"GET http://127.0.0.1:{self.origin_port}{path} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1\r\n{headers}\r\n").encode())
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def _assert_slots_recovered(self):
        # server_close joins all owned handler threads (non-daemon in this fixture).
        self.proxy.server_close()
        acquired = 0
        try:
            for _ in range(16):
                self.assertTrue(self.proxy.slots.acquire(blocking=False))
                acquired += 1
        finally:
            for _ in range(acquired):
                self.proxy.slots.release()

    def test_trickled_headers_and_body_share_total_deadline(self):
        with patch.object(egress_proxy, "_TOTAL_DEADLINE", 0.25):
            for path in ("/slow-header", "/slow-body"):
                started = time.monotonic()
                response = self._raw(path=path)
                self.assertLess(time.monotonic() - started, 1.5)
                if path == "/slow-body":
                    self.assertIn(b"200", response)
                    self.assertLess(len(response.split(b"\r\n\r\n", 1)[1]), 100)
                else:
                    self.assertNotIn(b"200 OK", response)
        self._assert_slots_recovered()

    def test_duplicate_length_and_transfer_encoding_refused_before_contact(self):
        with patch.object(egress_proxy.socket, "getaddrinfo", wraps=socket.getaddrinfo) as dns:
            for headers in ("Content-Length: 0\r\nContent-Length: 0\r\n",
                            "Transfer-Encoding: chunked\r\n"):
                self.assertIn(b"400", self._raw(headers))
            # Client loopback connections also resolve; no origin-port resolution.
            self.assertFalse(any(c.args[:2] == ("127.0.0.1", self.origin_port)
                                 for c in dns.call_args_list))
        self._assert_slots_recovered()

    def test_late_dns_and_connect_completion_send_zero_bytes(self):
        handler = object.__new__(egress_proxy._handler(frozenset()))
        handler.socket_lock = threading.Lock()
        handler.expired = False
        handler.upstream_socket = None
        fake = Mock()
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1))]
        def late_dns(*args, **kwargs):
            handler.deadline = time.monotonic() - 1
            return addresses
        handler.deadline = time.monotonic() + 10
        with patch.object(egress_proxy.socket, "getaddrinfo", side_effect=late_dns), \
             patch.object(egress_proxy.socket, "socket", return_value=fake) as create:
            with self.assertRaises(TimeoutError):
                handler._connect(("fake.invalid", 1))
            create.assert_not_called()
        handler.deadline = time.monotonic() + 10
        def late_connect(*args):
            handler.deadline = time.monotonic() - 1
        fake.connect.side_effect = late_connect
        with patch.object(egress_proxy.socket, "getaddrinfo", return_value=addresses), \
             patch.object(egress_proxy.socket, "socket", return_value=fake):
            with self.assertRaises(TimeoutError):
                handler._connect(("fake.invalid", 1))
        fake.close.assert_called_once()
        fake.sendall.assert_not_called()

    def test_late_dns_refuses_actual_forward_before_request_send(self):
        from email.message import Message
        handler = object.__new__(egress_proxy._handler(frozenset({"fake.invalid"})))
        handler.socket_lock = threading.Lock()
        handler.expired = False
        handler.upstream_socket = None
        handler.deadline = time.monotonic() + 10
        handler.path = "http://fake.invalid/action"
        handler.command = "POST"
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer fake-short"
        handler.send_error = Mock()
        def late_dns(*args, **kwargs):
            handler.deadline = time.monotonic() - 1
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1))]
        with patch.object(egress_proxy.socket, "getaddrinfo", side_effect=late_dns), \
             patch.object(egress_proxy.socket, "socket") as create, \
             patch.object(egress_proxy.http.client, "HTTPConnection") as connection:
            handler._forward()
        create.assert_not_called()
        connection.return_value.request.assert_not_called()
        connection.return_value.close.assert_called_once()
        handler.send_error.assert_called_once_with(502, "upstream failed")

    def test_connect_pump_uses_original_remaining_budget(self):
        deadline = time.monotonic() + 0.1
        with patch.object(egress_proxy.select, "select", return_value=([], [], [])) as wait:
            egress_proxy._pump(Mock(), Mock(), deadline)
        self.assertGreater(wait.call_args.args[3], 0)
        self.assertLessEqual(wait.call_args.args[3], 0.1)

    def _opener(self):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{self.proxy_port}"}))

    def _connect(self, target: str):
        s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return s, s.recv(200).split(b"\r\n", 1)[0]

    def test_http_to_allowed_host_is_forwarded(self):
        body = self._opener().open(f"http://127.0.0.1:{self.origin_port}/", timeout=5).read()
        self.assertEqual(body, b"origin-body")

    def test_http_to_denied_host_is_403(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._opener().open("http://blocked.invalid/", timeout=5)
        self.assertEqual(cm.exception.code, 403)
        cm.exception.close()  # release the error response body (no ResourceWarning)

    def test_connect_to_allowed_host_tunnels(self):
        s, status = self._connect(f"127.0.0.1:{self.echo_port}")
        self.addCleanup(s.close)
        self.assertIn(b"200", status)
        s.sendall(b"ping")
        self.assertEqual(s.recv(64), b"ping")

    def test_connect_to_denied_host_is_403(self):
        s, status = self._connect("blocked.invalid:443")
        self.addCleanup(s.close)
        self.assertIn(b"403", status)

    def test_connect_to_unlisted_port_is_403(self):
        s, status = self._connect(f"127.0.0.1:{self.origin_port}")
        self.addCleanup(s.close)
        self.assertIn(b"403", status)


if __name__ == "__main__":
    unittest.main()
