"""Bounded fake transports and direct-path refusal; no live providers."""
import io
import json
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from sps import transport
from sps.audit import AuditLogger
from sps.cli import _write_boot_id
from sps.client import SPSClient, BadResponse, TransportError
from sps.config import VaultBlock, InfisicalBlock
from sps.paths import atomic_write, private_parent
from sps.plugins.localfile import _Vault, _file_lock
from sps.plugins.hashicorp_vault import HashicorpVaultPlugin
from sps.plugins.infisical import InfisicalPlugin


class SecurityBounds(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def listener(self, respond, tls=None):
        class Handler(socketserver.BaseRequestHandler):
            def handle(inner):
                inner.request.settimeout(1)
                try:
                    if tls is not None:
                        inner.request = tls.wrap_socket(inner.request, server_side=True)
                    inner.request.recv(65536)
                    respond(inner.request)
                except OSError:
                    pass
                finally:
                    inner.request.close()
        server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        worker.start()
        def close():
            server.shutdown()
            server.server_close()
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.addCleanup(close)
        return server.server_address

    def test_private_new_directories_under_umask_and_refusals(self):
        old = os.umask(0o022)
        try:
            target = self.root / "one/two/state"
            atomic_write(target, b"original")
        finally:
            os.umask(old)
        for directory in (target.parent, target.parent.parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for mode in (0o755, 0o777):
            target.parent.chmod(mode)
            with self.assertRaises(PermissionError):
                atomic_write(target, b"changed")
            self.assertEqual(target.read_bytes(), b"original")
            self.assertEqual(target.parent.stat().st_mode & 0o777, mode)
        target.parent.chmod(0o700)
        target.parent.parent.chmod(0o770)
        with self.assertRaises(PermissionError):
            private_parent(target)

    def test_audit_public_and_backup_refused_unchanged(self):
        path = self.root / "audit"
        path.write_bytes(b"original")
        path.chmod(0o644)
        with self.assertRaises(PermissionError):
            AuditLogger(path)
        self.assertEqual(path.read_bytes(), b"original")
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        path.chmod(0o600)
        logger = AuditLogger(path, max_bytes=1024)
        backup = Path(str(path) + ".1")
        backup.symlink_to(path)
        with self.assertRaises(PermissionError):
            logger.event("refused")
        self.assertEqual(path.read_bytes(), b"original")

    def test_lock_aliases_and_foreign_files_refused_without_chmod(self):
        path = self.root / "vault"
        lock = Path(str(path) + ".lock")
        victim = self.root / "victim"
        victim.write_bytes(b"unchanged")
        victim.chmod(0o644)
        for hard in (False, True):
            if hard:
                os.link(victim, lock)
            else:
                lock.symlink_to(victim)
            with self.assertRaises((PermissionError, OSError)):
                with _file_lock(path):
                    self.fail("unsafe lock admitted")
            lock.unlink()
            self.assertEqual(victim.read_bytes(), b"unchanged")
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644)
        from sps.paths import check_file
        from types import SimpleNamespace
        info = victim.stat()
        with self.assertRaises(PermissionError):
            check_file(SimpleNamespace(st_mode=info.st_mode, st_nlink=1, st_uid=os.getuid()+1))

    def test_symlink_parent_vault_modes_and_failed_write(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PermissionError):
            atomic_write(alias / "state", b"no")
        vault = _Vault.init(self.root / "vault", "fake-passphrase")
        before = vault._path.read_bytes()
        vault._path.chmod(0o644)
        with self.assertRaises(PermissionError):
            vault.set("tool", "field", "new")
        self.assertEqual(vault._path.read_bytes(), before)
        vault._path.chmod(0o600)
        with mock.patch("sps.paths.os.replace", side_effect=OSError("fake failure")):
            with self.assertRaises(OSError):
                vault.set("tool", "field", "new")
        self.assertEqual(vault._path.read_bytes(), before)
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_boot_fixed_temp_link_trap_is_not_touched(self):
        victim = self.root / "victim"
        victim.write_bytes(b"unchanged")
        path = self.root / "boot"
        trap = self.root / "boot.tmp"
        trap.symlink_to(victim)
        _write_boot_id(path, "fake-id")
        self.assertEqual(victim.read_bytes(), b"unchanged")
        self.assertTrue(trap.is_symlink())
        self.assertEqual(path.read_text(), "fake-id\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_provider_trickled_headers_and_body_then_recovery(self):
        from sps.tests.test_client import _gen_self_signed, _tls_server_context
        cert, key, ca = _gen_self_signed(self.root)
        tls = _tls_server_context(cert, key)
        verified = ssl.create_default_context(cafile=ca)
        for secure in (False, True):
            for headers in (True, False):
                with self.subTest(secure=secure, headers=headers):
                    count = [0]
                    def respond(sock):
                        count[0] += 1
                        if count[0] == 1:
                            if not headers:
                                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n")
                            for _ in range(100):
                                sock.sendall(b"x")
                                time.sleep(.01)
                        else:
                            body = b'{"data":{"data":{"key":""}}}'
                            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                    host, port = self.listener(respond, tls=tls if secure else None)
                    scheme = "https" if secure else "http"
                    plugin = HashicorpVaultPlugin(VaultBlock(url=f"{scheme}://{host}:{port}", token="fake", mount="secret"), timeout=.25)
                    readers = []
                    original = transport._Reader.__init__
                    def capture(reader, sock, budget):
                        original(reader, sock, budget)
                        readers.append(reader)
                    with mock.patch("sps.transport.ssl.create_default_context", return_value=verified), mock.patch.object(transport._Reader, "__init__", capture):
                        start = time.monotonic()
                        with self.assertRaises(RuntimeError):
                            plugin.get_secret("key", "item")
                        elapsed = time.monotonic()-start
                        self.assertGreaterEqual(elapsed, .18)
                        self.assertLess(elapsed, .9)
                        plugin.timeout = 1
                        self.assertEqual(plugin.get_secret("key", "item"), "")
                    self.assertTrue(readers)
                    for reader in readers:
                        self.assertTrue(reader.closed)
                        self.assertTrue(reader._raw.closed)
                        self.assertEqual(reader.sock.fileno(), -1)

    def test_provider_delayed_healthy_bodies_http_and_verified_tls(self):
        from sps.tests.test_client import _gen_self_signed, _tls_server_context
        cert, key, ca = _gen_self_signed(self.root)
        tls = _tls_server_context(cert, key)
        verified = ssl.create_default_context(cafile=ca)
        self.assertEqual(verified.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(verified.check_hostname)
        for secure in (False, True):
            for chunked in (False, True):
                for value in ("fake-value", "v" * 40000):
                    with self.subTest(secure=secure, chunked=chunked, size=len(value)):
                        body = json.dumps({"data": {"data": {"key": value}}}).encode()
                        def respond(sock):
                            framing = (b"Transfer-Encoding: chunked" if chunked else
                                       b"Content-Length: " + str(len(body)).encode())
                            sock.sendall(b"HTTP/1.1 200 OK\r\n" + framing + b"\r\n\r\n")
                            time.sleep(.1)
                            for offset in range(0, len(body), 4093):
                                part = body[offset:offset+4093]
                                if chunked:
                                    sock.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                                else:
                                    sock.sendall(part)
                            if chunked:
                                sock.sendall(b"0\r\n\r\n")
                        host, port = self.listener(respond, tls=tls if secure else None)
                        scheme = "https" if secure else "http"
                        plugin = HashicorpVaultPlugin(VaultBlock(url=f"{scheme}://{host}:{port}", token="fake", mount="secret"), timeout=2)
                        readers = []
                        original = transport._Reader.__init__
                        def capture(reader, sock, budget):
                            original(reader, sock, budget)
                            readers.append(reader)
                        with mock.patch("sps.transport.ssl.create_default_context", return_value=verified), mock.patch.object(transport._Reader, "__init__", capture):
                            start = time.monotonic()
                            self.assertEqual(plugin.get_secret("key", "item"), value)
                            self.assertGreaterEqual(time.monotonic()-start, .09)
                        self.assertEqual(len(readers), 1)
                        self.assertTrue(readers[0].closed)
                        self.assertTrue(readers[0]._raw.closed)
                        self.assertEqual(readers[0].sock.fileno(), -1)

    def test_late_dns_connection_closed_before_credentials(self):
        host, port = self.listener(lambda sock: None)
        original = socket.getaddrinfo
        def late(*args, **kwargs):
            time.sleep(.06)
            return original(*args, **kwargs)
        plugin = HashicorpVaultPlugin(VaultBlock(url=f"http://{host}:{port}", token="fake", mount="secret"), timeout=.02)
        with mock.patch("socket.getaddrinfo", side_effect=late), mock.patch.object(transport._Socket, "sendall") as send:
            with self.assertRaises(RuntimeError):
                plugin.get_secret("key", "item")
            send.assert_not_called()
        client = SPSClient(host, port, timeout=.02)
        with mock.patch("socket.getaddrinfo", side_effect=late), mock.patch.object(client._ctx, "wrap_socket") as tls:
            with self.assertRaises(TransportError):
                client.ping()
            tls.assert_not_called()

    def test_provider_aggregate_cap_retry_budget_and_no_mutation_replay(self):
        budget = transport.Budget(1)
        token = transport._active.set(budget)
        try:
            transport.read_response(io.BytesIO(b"x" * (transport.MAX_RESPONSE - 1)))
            with self.assertRaises(ValueError):
                transport.read_response(io.BytesIO(b"xx"))
        finally:
            transport._active.reset(token)
        plugin = InfisicalPlugin(InfisicalBlock(host="http://127.0.0.1", client_id="fake", client_secret="fake", vault="fake"), timeout=.1)
        plugin._project_id = "fake"
        plugin._token = ("fake", time.time()+600)
        error = urllib.error.HTTPError("never-reflect", 503, "never-reflect", {}, io.BytesIO())
        with mock.patch("sps.transport.urlopen", side_effect=error) as call:
            with self.assertRaises(RuntimeError):
                plugin.get_secret("key", "item")
            self.assertEqual(call.call_count, 1)
        with mock.patch("sps.transport.urlopen", side_effect=urllib.error.URLError("never-reflect")) as call:
            with self.assertRaises(RuntimeError) as caught:
                plugin.write_secret("key", "item", "fake")
            self.assertNotIn("never-reflect", str(caught.exception))
            self.assertEqual(call.call_count, 1)

    def test_client_response_cap_and_lock_budget(self):
        client = SPSClient("127.0.0.1", 1, timeout=.03, max_response_bytes=1024)
        client._lock.acquire()
        try:
            with self.assertRaises(TransportError):
                client.ping()
        finally:
            client._lock.release()
        for timeout in (0, -1, float("inf"), float("nan"), 301):
            with self.assertRaises(ValueError):
                SPSClient("localhost", 1, timeout=timeout)
        for cap in (None, 1023, 32*1024*1024+1):
            with self.assertRaises(ValueError):
                SPSClient("localhost", 1, max_response_bytes=cap)

    def test_client_tls_oversize_and_trickle_recover(self):
        from sps.tests.test_client import _gen_self_signed, _tls_server_context
        cert, key, ca = _gen_self_signed(self.root)
        tls = _tls_server_context(cert, key)
        for oversize in (True, False):
            count = [0]
            def respond(sock):
                count[0] += 1
                if count[0] == 1:
                    if oversize:
                        sock.sendall(b"x" * 1025)
                    else:
                        for _ in range(50):
                            sock.sendall(b" ")
                            time.sleep(.01)
                else:
                    sock.sendall(b'{"status":"ok"}\n')
            host, port = self.listener(respond, tls=tls)
            client = SPSClient(host, port, ca_file=ca, timeout=.15, max_response_bytes=1024)
            start = time.monotonic()
            with self.assertRaises(BadResponse if oversize else TransportError):
                client.ping()
            elapsed = time.monotonic()-start
            if not oversize:
                self.assertGreaterEqual(elapsed, .10)
            self.assertLess(elapsed, .8)
            client._timeout = 1
            self.assertEqual(client.ping(), {"status": "ok"})

    def test_provider_redirect_not_followed(self):
        contacted = []
        host, port = self.listener(lambda sock: contacted.append(True))
        destination = f"http://{host}:{port}/trap"
        def redirect(sock):
            sock.sendall(b"HTTP/1.1 302 Found\r\nLocation: " + destination.encode() + b"\r\nContent-Length: 0\r\n\r\n")
        origin, origin_port = self.listener(redirect)
        plugin = HashicorpVaultPlugin(VaultBlock(url=f"http://{origin}:{origin_port}", token="fake", mount="secret"))
        with self.assertRaises(RuntimeError):
            plugin.get_secret("key", "item")
        self.assertEqual(contacted, [])
