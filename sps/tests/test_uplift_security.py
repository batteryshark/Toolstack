"""Offline regressions: fake capabilities/providers and isolated local state."""
import concurrent.futures
import io
import json
import multiprocessing
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import urllib.error
from unittest import mock

from sps import handlers
from sps.audit import AuditLogger
from sps.config import parse_bool, validate_provider_url, VaultBlock, InfisicalBlock
from sps.plugins.hashicorp_vault import HashicorpVaultPlugin
from sps.plugins.infisical import InfisicalPlugin
from sps.plugins.localfile import _Vault
from sps.server import build_server
from sps.server import ThreadingTCPServer
from sps.store import Registration, ToolRegistrationStore
from sps.wire import read_one_json


def _writer(path, field):
    _Vault(path, "fake-pass").set("tool", field, field)


class Security(unittest.TestCase):
    def test_absolute_body_deadline_defeats_dribble_and_audits_reject(self):
        audit = mock.Mock()
        ctx = SimpleNamespace(audit=audit, boot_id="fake")
        server = build_server(ctx, allow_plaintext_for_tests=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        stop = threading.Event()
        def dribble(conn):
            try:
                while not stop.wait(0.02):
                    conn.sendall(b" ")
            except OSError:
                pass
        with mock.patch("sps.server.BODY_TIMEOUT", 0.2), mock.patch("sps.server.SOCKET_TIMEOUT", 2):
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as conn:
                    sender = threading.Thread(target=dribble, args=(conn,))
                    started = time.monotonic()
                    sender.start()
                    try:
                        response = read_one_json(conn.makefile("rb"))
                        self.assertEqual(response["message"], "Bad request")
                        self.assertLess(time.monotonic() - started, 1.5)
                        self.assertFalse(any(call.kwargs.get("outcome") == "Bad request"
                                             for call in audit.event.call_args_list))
                    finally:
                        stop.set()
                        sender.join(2)
                with socket.create_connection(server.server_address, timeout=2) as conn:
                    conn.sendall(b'{"op":"ping"}\n')
                    self.assertEqual(read_one_json(conn.makefile("rb"))["status"], "ok")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)

    def test_missing_tls_fails_before_provider_connect(self):
        from sps.cli import _cmd_serve
        for cert, key in (("", ""), ("/nonexistent-fake-cert", "/nonexistent-fake-key")):
            cfg = SimpleNamespace(sp_tls_cert=cert, sp_tls_key=key)
            with mock.patch("sps.cli.cfgmod.load_config", return_value=cfg), mock.patch("sps.cli.plugin_loader.load_plugin") as load:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    _cmd_serve(SimpleNamespace(config="unused-fake-config"))
                load.assert_not_called()

    def test_vault_cas_conflict_is_not_retried_or_blindly_overwritten(self):
        from sps.tests.test_plugin_hashicorp import _StubResponse
        conflict = urllib.error.HTTPError("https://example.com", 400, "CAS mismatch", {}, io.BytesIO())
        plugin = HashicorpVaultPlugin(VaultBlock("https://example.com", "fake"))
        with mock.patch("sps.transport.urlopen", side_effect=[
                _StubResponse({"data": {"data": {"sibling": "fake"}, "metadata": {"version": 3}}}), conflict]) as call:
            with self.assertRaises(RuntimeError):
                plugin.write_secret("field", "item", "new-fake")
            self.assertEqual(call.call_count, 2)
            payload = json.loads(call.call_args.args[0].data)
            self.assertEqual(payload["options"], {"cas": 3})
            self.assertEqual(payload["data"]["sibling"], "fake")

    def test_handshake_admission_and_timeout_release_slot(self):
        from sps.tests.test_wire_end_to_end import _gen_self_signed, _tls_context
        class OneWorker(ThreadingTCPServer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, max_workers=1, **kwargs)
        with tempfile.TemporaryDirectory() as temp:
            cert, key = _gen_self_signed(Path(temp))
            ctx = SimpleNamespace(audit=mock.Mock(), boot_id="fake")
            server = build_server(ctx, ssl_ctx=_tls_context(cert, key), server_class=OneWorker)
            admitted = threading.Event()
            original = server.ssl_ctx.wrap_socket
            def wrap(*args, **kwargs):
                admitted.set()
                return original(*args, **kwargs)
            with mock.patch("sps.server.SOCKET_TIMEOUT", 0.3), mock.patch.object(server.ssl_ctx, "wrap_socket", side_effect=wrap):
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                slow = socket.create_connection(server.server_address)
                try:
                    self.assertTrue(admitted.wait(2))
                    with socket.create_connection(server.server_address, timeout=1) as excess:
                        self.assertEqual(excess.recv(1), b"")
                    # The listener is not doing this handshake: it accepted and
                    # rejected the excess peer while the sole worker was busy.
                    self.assertTrue(server._slots.acquire(timeout=2))
                    server._slots.release()
                    self.assertGreater(ctx.audit.event.call_count, 0)
                finally:
                    slow.close()
                    server.shutdown()
                    server.server_close()
                    thread.join()

    def test_boolean_and_provider_urls(self):
        for value in (True, "1", "True", "YES", "on"):
            self.assertTrue(parse_bool(value))
        for value in (False, "0", "False", "NO", "off"):
            self.assertFalse(parse_bool(value))
        for value in (None, 1, "", "typo"):
            with self.assertRaises(ValueError):
                parse_bool(value)
        for url in ("http://example.com", "ftp://localhost", "https://u:p@example.com", "https://example.com?q=x"):
            with self.assertRaises(ValueError):
                validate_provider_url(url)
        for url in ("http://127.0.0.1", "http://[::1]", "https://example.com"):
            self.assertEqual(validate_provider_url(url), url)

    def test_vault_paths(self):
        plugin = HashicorpVaultPlugin(VaultBlock("https://example.com", "fake"))
        for item in ("../other", "a/./b", "a?b", "a#b", "%2e%2e/a", "a//b", "a/%2f/b"):
            with self.assertRaises(ValueError):
                plugin._path(item)
        self.assertTrue(plugin._path("a space/child").endswith("a%20space/child"))

    def test_authenticated_snapshot_is_used_and_deeply_frozen(self):
        store = ToolRegistrationStore()
        entry = {"name": "key", "field": "old", "item": "tool", "writable": False}
        old = Registration("fake-old", (entry,))
        store.register("tool", old)
        entry["field"] = "mutated"
        with self.assertRaises(TypeError):
            old.secret_entries[0]["field"] = "mutated"
        original = store.get
        def replacing(tool):
            rec = original(tool)
            store.register(tool, Registration("fake-new", ({**entry, "field": "new"},)))
            return rec
        plugin = mock.Mock()
        plugin.get_secret.return_value = "fake-value"
        with mock.patch.object(store, "get", side_effect=replacing) as get:
            response = handlers.handle_get_secret(SimpleNamespace(store=store, plugin=plugin),
                {"toolid": "tool", "esecret": "fake-old", "name": "key"})
        self.assertEqual(get.call_count, 1)
        plugin.get_secret.assert_called_once_with("old", "tool")
        self.assertEqual(response["secrets"]["key"], "fake-value")

    def test_infisical_ambiguous_names_and_exact_id(self):
        plugin = InfisicalPlugin(InfisicalBlock("https://example.com", "target", client_id="fake", client_secret="fake"))
        projects = {"projects": [{"id": "1", "name": "target"}, {"id": "2", "slug": "target"}]}
        with mock.patch.object(plugin, "_http", return_value=projects):
            with self.assertRaises(ValueError):
                plugin._ensure_project_id()
        projects["projects"].append({"id": "target", "name": "other"})
        with mock.patch.object(plugin, "_http", return_value=projects):
            self.assertEqual(plugin._ensure_project_id(), "target")
        duplicate = InfisicalPlugin(InfisicalBlock("https://example.com", "target", client_id="fake", client_secret="fake"))
        with mock.patch.object(duplicate, "_http", return_value={"projects": [{"id": "target"}, {"_id": "target"}]}):
            with self.assertRaises(ValueError):
                duplicate._ensure_project_id()

    def test_localfile_concurrent_processes_and_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vault"
            first = _Vault.init(path, "fake-pass")
            processes = [multiprocessing.get_context("spawn").Process(target=_writer, args=(path, str(i))) for i in range(4)]
            for process in processes:
                process.start()
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(set(first.list_fields("tool")), {"0", "1", "2", "3"})
            with mock.patch("sps.plugins.localfile.os.replace", side_effect=OSError("fake failure")):
                with self.assertRaises(OSError):
                    first.set("tool", "lost", "fake")
            self.assertNotIn("lost", first._data["tool"])
            self.assertIsNone(first.get("tool", "lost"))
            self.assertEqual(list(Path(temp).glob("*.tmp")), [])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            second = _Vault(path, "fake-pass")
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda i: (first if i % 2 else second).set("tool", f"thread-{i}", "fake"), range(8)))
            self.assertEqual(len(first.list_fields("tool")), 12)
            from sps.plugins import localfile
            replace = localfile.os.replace
            observed = []
            def check_private(src, dst):
                observed.append(src)
                self.assertEqual(os.stat(src).st_mode & 0o777, 0o600)
                return replace(src, dst)
            with mock.patch.object(localfile.os, "replace", side_effect=check_private):
                first.set("tool", "check", "fake")
                first.set("tool", "check", "fake2")
            self.assertNotEqual(*observed)

    def test_rejects_and_audit_failure_before_reply(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "audit")
            ctx = SimpleNamespace(audit=audit, boot_id="fake",
                                  config=SimpleNamespace(sp_secret="fake-master"),
                                  store=ToolRegistrationStore())
            with self.assertRaises(ValueError):
                build_server(ctx)
            server = build_server(ctx, allow_plaintext_for_tests=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for body in (b"[]\n", b"not-json\n", b'{"op":"unknown","value":"never-log"}\n'):
                    with socket.create_connection(server.server_address) as conn:
                        conn.sendall(body)
                        self.assertEqual(read_one_json(conn.makefile("rb"))["message"], "Bad request")
                    records = Path(temp, "audit").read_text() if Path(temp, "audit").exists() else ""
                    self.assertNotIn("never-log", records)
                with socket.create_connection(server.server_address) as conn:
                    conn.sendall(b'{"op":"register","spsecret":"never-log","toolid":"fake-tool"}\n')
                    self.assertEqual(read_one_json(conn.makefile("rb"))["message"], "Unauthorized")
                    records = Path(temp, "audit").read_text() if Path(temp, "audit").exists() else ""
                    self.assertNotIn("Unauthorized", records)
                    self.assertNotIn("never-log", records)
                    self.assertNotIn("fake-tool", records)
                with mock.patch.object(audit, "event", side_effect=OSError("disk full")):
                    with socket.create_connection(server.server_address) as conn:
                        conn.sendall(b'{"op":"unregister","spsecret":"fake-master","toolid":"fake-tool"}\n')
                        self.assertEqual(read_one_json(conn.makefile("rb"))["message"], "Backend error")
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
