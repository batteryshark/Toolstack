"""Offline policy, retention and resource-limit regressions."""
import io
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.error import HTTPError

from sps import cli, handlers, server, transport
from sps.audit import AuditLogger
from sps.client import SPSClient
from sps.config import InfisicalBlock, VaultBlock, LocalFileBlock, load_config, validate_listener
from sps.plugins.hashicorp_vault import HashicorpVaultPlugin
from sps.plugins.localfile import _Vault, _vault_key, _write_vault
from sps.tests.test_register import _ctx, _reg_msg
from sps.tests.test_wire_end_to_end import _gen_self_signed, _tls_context
from sps.tool_sdk import SecretClient


def request(ctx, msg, instance=None):
    handler = object.__new__(server._StreamHandler)
    handler.connection = mock.Mock()
    handler.wfile = io.BytesIO()
    handler.ctx = ctx
    handler.server = instance or mock.Mock()
    with mock.patch("sps.server.read_socket_json", return_value=msg):
        handler.handle()
    return json.loads(handler.wfile.getvalue())


class PolicyLimits(unittest.TestCase):
    def test_registration_policy_and_hashed_audit(self):
        ctx = _ctx(audit=mock.Mock())
        message = _reg_msg(secrets=[{"name": "name", "field": "private-field", "item": "other/path", "writable": True}])
        self.assertEqual(request(ctx, message)["message"], "Unauthorized")
        self.assertIsNone(ctx.store.get("echo"))
        ctx.config = replace(ctx.config, grants={"echo": ("other/path",)})
        self.assertEqual(request(ctx, message)["status"], "ok")
        event = ctx.audit.event.call_args.kwargs
        self.assertEqual(event["entry_count"], 1)
        self.assertEqual(event["writable_count"], 1)
        self.assertTrue(all(v.startswith("sha256:") for v in event["entries"][0].values()))
        self.assertNotIn("private-field", repr(event))
        self.assertNotIn("other/path", repr(event))
        ctx.config = replace(ctx.config, grants={})
        self.assertEqual(request(ctx, message)["message"], "Unauthorized")
        self.assertEqual(ctx.store.get("echo").secret_entries[0]["item"], "other/path")
        for item in (None, "echo"):
            self.assertEqual(request(ctx, _reg_msg(secrets=[{"name": "n", "field": "f", "item": item}]))["status"], "ok")

    def test_ping_and_garbage_volume_is_rate_bounded(self):
        ctx = _ctx(audit=mock.Mock())
        ctx.boot_id = "fake"
        instance = object.__new__(server.ThreadingTCPServer)
        instance._reject_lock = threading.Lock()
        instance._rejects = dict.fromkeys(("admission", "transport", "ping", "invalid"), 0)
        instance._last_reject_audit = float("-inf")
        instance.RequestHandlerClass = SimpleNamespace(ctx=ctx)
        with mock.patch("sps.server.time.monotonic", return_value=1):
            for _ in range(500):
                for msg in ({"op": "ping"}, {"op": "garbage"}, [], {"op": "register"}):
                    request(ctx, msg, instance)
                    instance._flush_rejects()
        self.assertLessEqual(ctx.audit.event.call_count, 2)
        with mock.patch("sps.server.time.monotonic", return_value=2):
            instance._flush_rejects()
        self.assertEqual(sum(c.kwargs["count"] for c in ctx.audit.event.call_args_list), 2000)
        self.assertTrue(all(c.kwargs["outcome"] == "rejected" for c in ctx.audit.event.call_args_list))

    def test_audit_retains_generations_and_only_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            log = AuditLogger(Path(temp) / "audit", max_bytes=1024, generations=3)
            for i in range(100):
                log.event("register", tool_id=str(i))
            self.assertEqual(len(list(Path(temp).iterdir())), 4)
            with self.assertRaises(ValueError):
                log.event("register", entries=[{"field": "raw", "item": "raw"}], entry_count=1, writable_count=0)

    def test_tls_dribble_hits_absolute_deadline(self):
        with tempfile.TemporaryDirectory() as temp:
            cert, key = _gen_self_signed(Path(temp))
            tls = _tls_context(cert, key)
            client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            peer = client.wrap_bio(incoming, outgoing, server_hostname="localhost")
            with self.assertRaises(ssl.SSLWantReadError):
                peer.do_handshake()
            hello = outgoing.read()
            left, right = socket.socketpair()
            wrapped = tls.wrap_socket(left, server_side=True, do_handshake_on_connect=False)
            stop = threading.Event()
            sent = []
            def dribble():
                try:
                    for byte in hello:
                        if stop.wait(0.02):
                            return
                        right.sendall(bytes([byte]))
                        sent.append(byte)
                except OSError:
                    pass
            thread = threading.Thread(target=dribble)
            thread.start()
            start = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    server.handshake_with_deadline(wrapped, 0.25)
                self.assertLess(time.monotonic() - start, 0.8)
                self.assertGreater(len(sent), 3)
            finally:
                stop.set()
                thread.join(2)
                wrapped.close()
                right.close()

    def test_bulk_http_error_closes_and_timeout_maps_to_backend(self):
        ctx = _ctx(audit=mock.Mock())
        handlers.handle_register(ctx, _reg_msg())
        ctx.plugin = HashicorpVaultPlugin(VaultBlock("https://example.invalid", "fake"))
        body = io.BytesIO(b"private-provider-body")
        error = HTTPError("https://example.invalid", 403, "private", {}, body)
        for failure in (error, TimeoutError("private")):
            with mock.patch("sps.transport.urlopen", side_effect=failure):
                result = request(ctx, {"op": "get_secrets", "toolid": "echo", "esecret": _reg_msg()["esecret"]})
            self.assertEqual(result, {"status": "error", "message": "Backend error"})
            self.assertIsNone(transport._active.get())
        self.assertTrue(body.closed)

    def test_unknown_tool_and_wrong_secret_have_identical_response(self):
        ctx = _ctx(audit=mock.Mock())
        ctx.plugin.timeout = 15.0
        handlers.handle_register(ctx, _reg_msg())
        for op in ("get_secrets", "get_secret", "write_secret"):
            results = []
            with mock.patch("sps.handlers.constant_time_eq", wraps=handlers.constant_time_eq) as compare:
                for tool in ("echo", "unknown"):
                    results.append(request(ctx, {"op": op, "toolid": tool, "esecret": "wrong", "name": "api_key", "value": "x"}))
                self.assertEqual(compare.call_count, 2)
            self.assertEqual(results, [{"status": "error", "message": "Unauthorized"}] * 2)

    def test_credential_representations(self):
        secret = "unique-private-credential"
        objects = [replace(_ctx().config, sp_secret=secret), VaultBlock("https://example.invalid", secret),
                   InfisicalBlock("https://example.invalid", "vault", client_secret=secret),
                   SPSClient("localhost", 1, sp_secret=secret, esecret=secret)]
        for obj in objects:
            self.assertNotIn(secret, repr(obj))

    def test_cli_file_passphrase(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "passphrase"
            path.write_text("fake-passphrase\n")
            path.chmod(0o600)
            cfg = replace(_ctx().config, sp_plugin="localfile", localfile=LocalFileBlock("unused"))
            args = SimpleNamespace(config="unused", tool="tool", field="field")
            with mock.patch.dict(os.environ, {"SP_VAULT_PASSPHRASE_FILE": str(path)}, clear=True), mock.patch("sps.cli.cfgmod.load_config", return_value=cfg), mock.patch("sps.plugins.localfile._Vault") as vault, mock.patch("sys.stdin", io.StringIO("fake-value\n")), mock.patch("builtins.print"):
                cli._cmd_vault_set(args)
                cli._cmd_vault_get(args)
                self.assertEqual(vault.call_count, 2)
                self.assertTrue(all(c.args == ("unused", "fake-passphrase") for c in vault.call_args_list))
                path.chmod(0o644)
                with self.assertRaises((PermissionError, ValueError)):
                    cli._cmd_vault_get(args)

    def test_write_value_utf8_byte_limit(self):
        ctx = _ctx(audit=mock.Mock())
        handlers.handle_register(ctx, _reg_msg(secrets=[{"name": "key", "field": "f", "writable": True}]))
        base = {"op": "write_secret", "toolid": "echo", "esecret": _reg_msg()["esecret"], "name": "key"}
        for value in ("x" * 65536, "é" * 32768, ""):
            self.assertEqual(request(ctx, {**base, "value": value})["status"], "ok")
        ctx.plugin.reset_mock()
        for value in ("x" * 65537, "é" * 32769, "\ud800"):
            self.assertEqual(request(ctx, {**base, "value": value})["message"], "Bad request")
        ctx.plugin.write_secret.assert_not_called()
        ctx.config = replace(ctx.config, sp_max_value_bytes=2)
        self.assertEqual(request(ctx, {**base, "value": "abc"})["message"], "Bad request")

    def test_config_grants_and_listener_opt_in(self):
        for host in ("localhost", "127.0.0.1", "::1"):
            validate_listener(host)
        for host in ("0.0.0.0", "::", "example.invalid"):
            with self.assertRaises(ValueError):
                validate_listener(host)
            validate_listener(host, True)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sps.env"
            base = 'SP_HOST="0.0.0.0"\nSP_PORT="1"\nSP_SECRET="fake"\nSP_PLUGIN="localfile"\n'
            path.write_text(base)
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text(base + 'SP_ALLOW_NONLOOPBACK="1"\nSP_MAX_VALUE_BYTES=2048\n[grants]\necho=["shared/path"]\n')
            cfg = load_config(path)
            self.assertEqual(cfg.grants, {"echo": ("shared/path",)})
            self.assertEqual(cfg.sp_max_value_bytes, 2048)
            for extra in ('SP_ALLOW_NONLOOPBACK="typo"', 'SP_ALLOW_NONLOOPBACK=true\nSP_MAX_VALUE_BYTES=0', 'SP_ALLOW_NONLOOPBACK=true\n[grants]\necho="*"'):
                path.write_text(base + extra)
                with self.assertRaises(ValueError):
                    load_config(path)

    def test_new_and_legacy_vault_parameters(self):
        with tempfile.TemporaryDirectory() as temp:
            new, old = Path(temp) / "new", Path(temp) / "old"
            _Vault.init(new, "fake-pass")
            self.assertEqual(json.loads(new.read_text())["n"], 2 ** 16)
            salt = b"0123456789abcdef"
            params = (2 ** 14, 8, 1)
            _write_vault(old, salt, _vault_key("fake-pass", salt, *params), {"tool": {"f": "old"}}, params)
            vault = _Vault(old, "fake-pass")
            self.assertEqual(vault.get("tool", "f"), "old")
            vault.set("tool", "f", "new")
            self.assertEqual(json.loads(old.read_text())["n"], 2 ** 14)

    def test_loopback_certificate_lifetime_and_warning(self):
        with tempfile.TemporaryDirectory() as temp:
            cert, key, ca = (str(Path(temp) / name) for name in ("cert", "key", "ca"))
            cli.maybe_generate_tls_material(cert, key, ca, "/CN=127.0.0.1")
            expires = ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(cert)["notAfter"])
            self.assertGreater(expires - time.time(), 3000 * 86400)
            for days, expected in ((31, False), (29, True), (-1, True)):
                with mock.patch("time.time", return_value=expires - days * 86400), mock.patch("sys.stderr", io.StringIO()) as err:
                    cli.warn_certificate_expiry(cert)
                    self.assertEqual(bool(err.getvalue()), expected)

    def test_fake_sdk_refuses_present_credentials(self):
        for credential in ("fake", ""):
            with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_FAKE": "1", "TOOLSTACK_E_SECRET": credential}, clear=True):
                with self.assertRaises(RuntimeError):
                    SecretClient.from_env("echo")
        with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_FAKE": "1"}, clear=True):
            self.assertEqual(SecretClient.from_env("echo").names(), ())
