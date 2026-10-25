"""Bounded offline regressions for lead-adjudicated SPS followup."""
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from sps import handlers, server, wire
from sps.audit import AuditLogger
from sps.client import SPSClient, BadResponse, SPSError, TransportError
from sps.plugins.localfile import _Vault
from sps.store import Registration, ToolRegistrationStore


class Defects(unittest.TestCase):
    def test_registration_validation_and_unicode_auth(self):
        entry = {"name": "key", "field": "field"}
        for entries in ([entry, entry], [{**entry, "item": ""}]):
            with self.assertRaises(handlers.BadRegistration):
                handlers.parse_cs_tuples(entries)
        ctx = SimpleNamespace(config=SimpleNamespace(sp_secret="fake"),
                              store=ToolRegistrationStore())
        with self.assertRaises(handlers.BadRegistration):
            handlers.handle_register(ctx, {"spsecret": "fake", "toolid": "tool",
                "esecret": "a" * 32 + "\n", "secrets": []})
        ctx.store.register("tool", Registration("fake", ()))
        for credential in ("é", "\ud800"):
            with self.assertRaises(handlers.AuthError):
                handlers.check_sp(ctx, {"spsecret": credential})
            with self.assertRaises(handlers.AuthError):
                handlers.check_es(ctx, "tool", {"esecret": credential})

    def test_wire_exact_byte_cap_and_required_newline(self):
        limit = wire.MAX_BODY_BYTES
        good = b'{}' + b' ' * (limit - 3) + b'\n'
        for payload, error in ((good, None), (good[:-1] + b' \n', wire.OversizedBodyError),
                               (b'{}', ValueError), (good[:-1], ValueError),
                               (b'{}' + b' ' * (limit - 1), wire.OversizedBodyError)):
            for reader in ("file", "socket"):
                if reader == "file":
                    read = lambda: wire.read_one_json(io.BytesIO(payload))
                else:
                    sock = mock.Mock()
                    chunks = [payload[i:i+65536] for i in range(0, len(payload), 65536)]
                    sock.recv.side_effect = chunks + [b'']
                    read = lambda: wire.read_socket_json(sock, timeout=5)
                if error:
                    with self.assertRaises(error):
                        read()
                else:
                    self.assertEqual(read(), {})
        with self.assertRaises(wire.OversizedBodyError):
            wire.read_one_json(io.StringIO('"' + 'é' * (limit // 2) + '"\n'))

    def test_client_secret_shape_and_empty_value(self):
        client = SPSClient("localhost", 1, esecret="fake")
        for body in ({}, [], {"status": "ok"}, {"status": "ok", "secrets": []},
                     {"status": "ok", "secrets": {}},
                     {"status": "ok", "secrets": {"key": 1}}):
            with mock.patch.object(client, "_call", return_value=body):
                with self.assertRaises(BadResponse):
                    client.get_secret("tool", "key")
        with mock.patch.object(client, "_call", return_value={"status": "ok", "secrets": {"key": ""}}):
            self.assertEqual(client.get_secret("tool", "key"), "")

    def test_client_fixed_transport_and_envelope_errors(self):
        client = SPSClient("localhost", 1)
        for failure in (ConnectionRefusedError("never-log"), ssl.SSLError("never-log"), TimeoutError("never-log")):
            with mock.patch("sps.client.connect_socket", side_effect=failure):
                with self.assertRaises(TransportError) as caught:
                    client.ping()
                self.assertIsInstance(caught.exception, (SPSError, OSError))
                self.assertEqual(str(caught.exception), type(failure).__name__)
        for payload in (b'[]\n', b'{"status":"error","message":"never-log"}\n',
                        b'{"status":"other","value":"never-log"}\n', b'\xff\n', b'{}'):
            connection = mock.MagicMock()
            connection.__enter__.return_value = connection
            connection.makefile.return_value = io.BytesIO(payload)
            with mock.patch("sps.client.connect_socket", return_value=connection), mock.patch.object(client._ctx, "wrap_socket", return_value=connection), mock.patch("sps.client._Socket", return_value=connection):
                with self.assertRaises(BadResponse) as caught:
                    client.ping()
                self.assertNotIn("never-log", str(caught.exception))

    def test_admission_has_no_audit_io_and_summaries_rate_bound(self):
        audit = mock.Mock()
        handler = type("Handler", (), {"ctx": SimpleNamespace(audit=audit)})
        instance = server.ThreadingTCPServer(("127.0.0.1", 0), handler, max_workers=32)
        self.addCleanup(instance.server_close)
        self.assertGreaterEqual(instance.request_queue_size, 32)
        for _ in range(32):
            instance._slots.acquire()
        with mock.patch.object(instance, "shutdown_request"):
            for _ in range(100):
                instance.process_request(mock.Mock(), ("127.0.0.1", 0))
        audit.event.assert_not_called()
        instance._record_reject("transport")
        with mock.patch("sps.server.time.monotonic", return_value=1):
            instance._flush_rejects()
            instance._record_reject("transport")
            instance._flush_rejects()
        self.assertEqual(audit.event.call_count, 2)
        audit.event.assert_any_call("admission", outcome="rejected", count=100)
        audit.event.assert_any_call("transport", outcome="rejected", count=1)
        with mock.patch("sps.server.time.monotonic", return_value=2), mock.patch.object(audit, "event", side_effect=OSError("fake")):
            instance._flush_rejects()  # operational failure is best effort

    def test_reply_timeout_outcome_and_disconnect_sanitization(self):
        for failure in (ValueError("fake"), wire.OversizedBodyError("fake"), None):
            handler = object.__new__(server._StreamHandler)
            handler.connection = mock.Mock()
            handler.wfile = mock.Mock()
            handler.ctx = SimpleNamespace(audit=mock.Mock(), boot_id="fake")
            handler.server = mock.Mock()
            with mock.patch("sps.server.read_socket_json", side_effect=failure, return_value={"op": "ping"}), mock.patch.dict(server._HANDLER_BY_OP, {"ping": lambda *_: {"status": "ok", "message": "never-log"}}), mock.patch("sps.server.write_one_json", side_effect=BrokenPipeError("never-log")):
                handler.handle()
            self.assertEqual(handler.connection.settimeout.call_args.args, (server.SOCKET_TIMEOUT,))
            handler.ctx.audit.event.assert_not_called()
            handler.server._record_reject.assert_called_once_with("ping" if failure is None else "invalid")
        with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            server.ThreadingTCPServer.handle_error(None, None, None)
            self.assertEqual(stderr.getvalue(), "")

    def test_audit_rotation_is_bounded_private_and_failure_propagates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit"
            audit = AuditLogger(path, max_bytes=4096)
            for _ in range(200):
                audit.event("ping", tool_id="x" * 128)
            self.assertEqual(set(p.name for p in Path(temp).iterdir()), {"audit", *(f"audit.{i}" for i in range(1, 6))})
            for file in Path(temp).iterdir():
                self.assertLessEqual(file.stat().st_size, 4096)
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                for line in file.read_text().splitlines():
                    json.loads(line)
            with mock.patch("sps.audit.os.fsync", side_effect=OSError("fake")):
                with self.assertRaises(OSError):
                    audit.event("ping")

    def test_vault_parent_fsync_and_legacy_parameter_reload(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vault"
            vault = _Vault.init(path, "fake-pass")
            envelope = json.loads(path.read_text())
            for key in ("n", "r", "p"):
                envelope[key] = str(envelope[key])
            path.write_text(json.dumps(envelope))
            vault = _Vault(path, "fake-pass")
            self.assertIsNone(vault.get("tool", "field"))
            observed = []
            fsync = os.fsync
            def sync(fd):
                observed.append(stat.S_ISDIR(os.fstat(fd).st_mode))
                return fsync(fd)
            with mock.patch("sps.plugins.localfile.os.fsync", side_effect=sync):
                vault.set("tool", "field", "fake")
            self.assertEqual(observed, [False, True])
            self.assertEqual(vault.get("tool", "field"), "fake")
