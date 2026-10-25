"""Desktop shell lifecycle (stdlib, hermetic). Exercises the start / health / stop logic
with a fake admin (and a fake serve command), never the real admin or pywebview; the GUI
window is verified out of band (a screenshot). pywebview is not imported here."""

import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from desktop.app import DEFAULT_URL, Stack, _admin_url, _port_of, admin_healthy
from desktop.app import main, StartupRecovery, startup_error


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _FakeAdmin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/login" else 404)
        self.end_headers()

    def log_message(self, *a):
        pass


def _start_fake_admin():
    server = HTTPServer(("127.0.0.1", 0), _FakeAdmin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


# A serve command that starts a /login-serving HTTP server on the given port, then idles;
# stands in for `python -m admin serve` without needing FastAPI.
def _fake_serve_cmd(port: int) -> list[str]:
    code = (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def do_GET(s):\n"
        "        s.send_response(200 if s.path=='/login' else 404); s.end_headers()\n"
        "    def log_message(s,*a): pass\n"
        f"HTTPServer(('127.0.0.1',{port}), H).serve_forever()\n"
    )
    return [sys.executable, "-c", code]


class Health(unittest.TestCase):
    def test_false_when_nothing_listening(self):
        self.assertFalse(admin_healthy(f"http://127.0.0.1:{_free_port()}", timeout=0.5))

    def test_true_when_serving(self):
        server, url = _start_fake_admin()
        self.addCleanup(server.server_close)  # LIFO: runs after shutdown -> closes the socket
        self.addCleanup(server.shutdown)
        self.assertTrue(admin_healthy(url))


class Lifecycle(unittest.TestCase):
    def test_already_up_does_not_spawn(self):
        server, url = _start_fake_admin()
        self.addCleanup(server.server_close)  # LIFO: runs after shutdown -> closes the socket
        self.addCleanup(server.shutdown)
        # serve_cmd would fail loudly if run; proves ensure_up did NOT start its own admin
        stack = Stack(url, serve_cmd=[sys.executable, "-c", "raise SystemExit('must not run')"])
        stack.ensure_up()
        self.assertFalse(stack.started_admin())

    def test_early_exit_raises_with_guidance(self):
        url = f"http://127.0.0.1:{_free_port()}"  # nothing listening
        stack = Stack(url, serve_cmd=[sys.executable, "-c", "raise SystemExit(1)"])  # exits at once
        with self.assertRaises(RuntimeError) as cm:
            stack.ensure_up(tries=40)
        self.assertIn("set-password", str(cm.exception))  # points the user at the fix
        self.assertFalse(stack.started_admin())  # cleared after the early exit

    def test_spawns_waits_for_health_then_stops(self):
        port = _free_port()
        url = f"http://127.0.0.1:{port}"
        stack = Stack(url, serve_cmd=_fake_serve_cmd(port))
        self.addCleanup(stack.stop)
        stack.ensure_up(tries=80)
        self.assertTrue(stack.started_admin())
        self.assertTrue(admin_healthy(url))     # the spawned server is serving
        stack.stop()
        self.assertFalse(admin_healthy(url))     # ...and gone after stop
        self.assertFalse(stack.started_admin())

    def test_stop_is_idempotent_and_safe_when_never_started(self):
        stack = Stack("http://127.0.0.1:1")
        stack.stop()  # never started anything, must not raise
        self.assertFalse(stack.started_admin())


class PortOf(unittest.TestCase):
    def test_extracts_or_defaults(self):
        self.assertEqual(_port_of("http://127.0.0.1:8780"), "8780")
        self.assertEqual(_port_of("http://127.0.0.1:9001/"), "9001")
        self.assertEqual(_port_of("http://localhost"), "8780")  # no port -> default
        self.assertEqual(_port_of("http://127.0.0.1:8780/x?a=1:2"), "8780")  # colon in path


class AdminUrl(unittest.TestCase):
    def test_defaults_to_loopback_8780(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TOOLSTACK_ADMIN_URL", None)
            self.assertEqual(_admin_url(), DEFAULT_URL)

    def test_env_override(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_ADMIN_URL": "http://127.0.0.1:8799"}):
            self.assertEqual(_admin_url(), "http://127.0.0.1:8799")


class StartupSurface(unittest.TestCase):
    def test_retry_latch_and_close_during_startup(self):
        entered, release = threading.Event(), threading.Event()
        stack = mock.Mock(url='http://127.0.0.1:1')
        def wait_for_release():
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test release timeout')
        stack.ensure_up.side_effect = wait_for_release
        bridge = StartupRecovery(stack)
        bridge.window = mock.Mock()
        worker = threading.Thread(target=bridge.retry)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            bridge.retry()
            stack.ensure_up.assert_called_once()
            bridge.close()
        finally:
            release.set()
            worker.join(3)
            bridge.shutdown()
        self.assertFalse(worker.is_alive())
        bridge.window.load_url.assert_not_called()
        stack.stop.assert_called_once()
        bridge.retry()
        stack.ensure_up.assert_called_once()

    def test_double_click_failure_renders_before_main_and_cleans_up(self):
        stack = mock.Mock(url="http://127.0.0.1:1")
        stack.ensure_up.side_effect = RuntimeError("exit status 7")
        webview = mock.Mock()
        with mock.patch("desktop.app.Stack", return_value=stack), mock.patch.dict(
                sys.modules, {"webview": webview}):
            main()
        args, kwargs = webview.create_window.call_args
        self.assertEqual(args, ("Toolstack · Startup",))
        self.assertIn(stack.url, kwargs["html"])
        self.assertIn("exit status 7", kwargs["html"])
        self.assertIn("Diagnostics", kwargs["html"])
        self.assertIn("Retry", kwargs["html"])
        webview.start.assert_called_once()
        stack.stop.assert_called_once()

    def test_retry_failure_stays_local_then_success_opens_admin(self):
        stack = mock.Mock(url="http://127.0.0.1:1")
        stack.ensure_up.side_effect = [OSError("unavailable"), None]
        bridge = StartupRecovery(stack)
        bridge.window = mock.Mock()
        bridge.retry()
        bridge.window.load_url.assert_not_called()
        self.assertIn("unavailable", bridge.window.load_html.call_args.args[0])
        bridge.retry()
        bridge.window.load_url.assert_called_once_with(stack.url)
        bridge.close()
        bridge.window.destroy.assert_called_once()

    def test_error_is_escaped(self):
        self.assertNotIn("<script>", startup_error("<script>", "<script>"))


if __name__ == "__main__":
    unittest.main()
