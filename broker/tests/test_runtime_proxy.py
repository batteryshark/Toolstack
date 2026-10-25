"""Import-time proxy isolation with only owned loopback endpoints/fake secrets."""
from contextlib import contextmanager, ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess
import sys
import threading
import unittest

from .test_runtime import _FakeTool, _FakeRestForwarder, _FakeMcpTool


_PROBE = """
import sys
import urllib.request

# This process has only the synthetic environment supplied by the test. Verify
# the proxy is effective before importing runtime and constructing its opener.
assert urllib.request.getproxies()["http"] == sys.argv[4]
assert not urllib.request.proxy_bypass("127.0.0.1")
from broker.runtime import HttpRuntime, _OPENER, _NoRedirect
from broker.bounds import DeadlineHTTPHandler
from broker.registry import ToolOp

runtime = HttpRuntime(timeout=2, tool_secret=lambda _: "fake-channel-only")
for kind, port in zip(("api", "rest", "mcp"), sys.argv[1:4]):
    result = runtime.execute(ToolOp("fake", "say", "read", int(port), kind),
                             {"message": "fake-body-only"}, 7, "fake-caller")
    assert isinstance(result, dict)
assert any(isinstance(h, _NoRedirect) for h in _OPENER.handlers)
assert any(isinstance(h, DeadlineHTTPHandler) for h in _OPENER.handlers)
assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
               for h in _OPENER.handlers)
"""


class RuntimeProxy(unittest.TestCase):
    @contextmanager
    def serving(self, handler):
        # Bound accepted reads too, so an interrupted probe cannot leave a
        # fixture handler waiting indefinitely for its request body.
        class Bounded(handler):
            def setup(self):
                self.request.settimeout(2)
                super().setup()
        server = HTTPServer(("127.0.0.1", 0), Bounded)
        worker = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            yield server.server_address[1], Bounded
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(server.socket.fileno(), -1)

    def test_all_tool_hops_ignore_proxy_captured_at_import(self):
        class ProxyTrap(BaseHTTPRequestHandler):
            received = []

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.received.append((self.path, self.headers.get("X-Toolstack-Secret"), body))
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        with ExitStack() as stack:
            api_port, api = stack.enter_context(self.serving(_FakeTool))
            rest_port, rest = stack.enter_context(self.serving(_FakeRestForwarder))
            mcp_port, mcp = stack.enter_context(self.serving(_FakeMcpTool))
            proxy_port, proxy = stack.enter_context(self.serving(ProxyTrap))
            # Subclass-local fixture state: do not mutate the imported fixtures.
            api.received = rest.received = None
            rest.status = 200
            rest.response = {"status": 200, "headers": {}, "body": "ok"}
            mcp.received = []
            mcp.mode, mcp.tool_result = "json", None
            mcp.force_error, mcp.is_error, mcp.bad_init = None, False, False
            proxy_url = f"http://127.0.0.1:{proxy_port}"
            result = subprocess.run(
                [sys.executable, "-c", _PROBE, str(api_port), str(rest_port), str(mcp_port), proxy_url],
                cwd=Path(__file__).resolve().parents[2],
                env={"HTTP_PROXY": proxy_url, "NO_PROXY": "", "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(proxy.received, [], "tool traffic reached the proxy trap")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(api.received["path"], "/v1/actions/say")
            self.assertEqual(rest.received["path"], "/sendrequest")
            for received in (api.received, rest.received):
                self.assertEqual(received["shared_secret"], "fake-channel-only")
                self.assertEqual(received["body"]["arguments"], {"message": "fake-body-only"})
            self.assertEqual([r["method"] for r in mcp.received],
                             ["initialize", "notifications/initialized", "tools/call"])
            self.assertEqual([r["secret"] for r in mcp.received], ["fake-channel-only"] * 3)
            self.assertEqual(mcp.received[-1]["message"]["params"]["arguments"],
                             {"message": "fake-body-only"})


if __name__ == "__main__":
    unittest.main()
