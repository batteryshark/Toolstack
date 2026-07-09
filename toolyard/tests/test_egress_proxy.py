"""Egress proxy: it forwards a request to a host on the allowlist and refuses (403) any
other host, for both plain HTTP and CONNECT tunnels. Exercised against local servers, so it
is deterministic and needs no external network.
"""

import socket
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from toolyard.egress_proxy import serve


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
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.addCleanup(self.origin.server_close)
        self.addCleanup(self.origin.shutdown)
        self.origin_port = self.origin.server_address[1]

        self.echo = socket.socket()
        self.echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.echo.bind(("127.0.0.1", 0))
        self.echo.listen(1)
        self.echo_port = self.echo.getsockname()[1]
        threading.Thread(target=self._echo_serve, daemon=True).start()
        self.addCleanup(self.echo.close)

        self.proxy = serve(_free_port(), ["127.0.0.1"])
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.addCleanup(self.proxy.server_close)
        self.addCleanup(self.proxy.shutdown)
        self.proxy_port = self.proxy.server_address[1]

    def _echo_serve(self):
        while True:
            try:
                conn, _ = self.echo.accept()
            except OSError:
                return
            threading.Thread(target=lambda c=conn: (c.sendall(c.recv(64)), c.close()),
                             daemon=True).start()

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


if __name__ == "__main__":
    unittest.main()
