"""client: SPSClient TCP/TLS round-trip (against an in-process SPS server)."""
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from dataclasses import make_dataclass
from pathlib import Path

from sps.audit import AuditLogger
from sps.client import (
    AuthError,
    BackendError,
    NotFound,
    NotWritable,
    SPSClient,
    SPSError,
)
from sps.config import Config
from sps.server import build_server
from sps.store import ToolRegistrationStore


def _gen_self_signed(tmpdir: Path) -> tuple[str, str, str]:
    cert = tmpdir / "s.crt"
    key = tmpdir / "s.key"
    ca = tmpdir / "s.ca"
    # SAN with `IP:127.0.0.1` so hostname verification (which prefers SAN
    # over legacy CN) accepts the loopback address.
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName = IP:127.0.0.1,DNS:localhost",
    ], check=True, capture_output=True)
    ca.write_bytes(cert.read_bytes())  # self-signed == own CA in dev
    return str(cert), str(key), str(ca)


def _tls_server_context(cert, key) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


class _FakePlugin:
    def get_secret(self, field, item):
        if field == "API_KEY":
            return "V"
        raise KeyError(field)

    def write_secret(self, field, item, value):
        pass


class _FakeAudit:
    def event(self, action, *, tool_id="", secret_name=""):
        pass


class _ServerHarness:
    """TLS server in a background thread for the client to talk to."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup = lambda f: f
        self.cert, self.key, self.ca = _gen_self_signed(self.tmp)
        store = ToolRegistrationStore()
        store.register("echo", None)  # not used; we just need an SPS up
        self.store = store
        cfg = Config(
            sp_host="127.0.0.1", sp_port=0, sp_secret="sp-1",
            sp_tls_cert=self.cert, sp_tls_key=self.key, sp_tls_ca=self.ca,
            sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
            infisical=None, vault=None, localfile=None,
        )
        AppCtx = make_dataclass("AppCtx", ["config", "store", "audit", "plugin"])
        ctx = AppCtx(config=cfg, store=store, audit=_FakeAudit(), plugin=_FakePlugin())
        ssl_ctx = _tls_server_context(self.cert, self.key)
        server = build_server(ctx, host="127.0.0.1", port=0, ssl_ctx=ssl_ctx)
        self.port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.server = server
        self.thread = thread

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class Client(unittest.TestCase):
    def setUp(self):
        self.srv = _ServerHarness()
        self.addCleanup(self.srv.shutdown)
        self.ca = self.srv.ca

    def test_register_and_get_secrets_round_trip(self):
        c = SPSClient("127.0.0.1", self.srv.port,
                     sp_secret="sp-1", ca_file=self.ca)
        esecret = "e" + "1" * 63
        c.register("echo", esecret, [
            {"name": "api_key", "field": "API_KEY", "item": "echo", "writable": False},
        ])
        secrets = c.get_secrets("echo", esecret) if False else None  # type: ignore
        # The client takes only esecret in __init__ for ES callers; adapt the
        # call shape to match the simpler API.
        c_es = SPSClient("127.0.0.1", self.srv.port,
                        esecret=esecret, ca_file=self.ca)
        secrets = c_es.get_secrets("echo")
        self.assertEqual(secrets.get("secrets"), {"api_key": "V"})

    def test_unauthorized_for_wrong_sp(self):
        c = SPSClient("127.0.0.1", self.srv.port,
                     sp_secret="wrong", ca_file=self.ca)
        with self.assertRaises(AuthError):
            c.register("echo", "e" + "1" * 63, [])

    def test_write_secret_200(self):
        sp = SPSClient("127.0.0.1", self.srv.port,
                       sp_secret="sp-1", ca_file=self.ca)
        esecret = "e" + "2" * 63
        sp.register("echo", esecret, [
            {"name": "api_key", "field": "API_KEY", "item": "echo", "writable": True},
        ])
        es = SPSClient("127.0.0.1", self.srv.port,
                       esecret=esecret, ca_file=self.ca)
        # The FakePlugin accepts writes silently; the SPS returns ok.
        es.write_secret("echo", "api_key", "V-new")

    def test_not_found_propagates(self):
        es = SPSClient("127.0.0.1", self.srv.port,
                       esecret="e" + "3" * 63, ca_file=self.ca)
        with self.assertRaises(NotFound):
            es.get_secrets("never-registered")

    def test_bad_ca_fails_closed(self):
        # Point at a missing CA file: client should fail at construction
        # time (load_verify_locations raises FileNotFoundError) so we never
        # silently fall back to system trust for an SPS server.
        with self.assertRaises((SPSError, OSError, FileNotFoundError)):
            SPSClient("127.0.0.1", self.srv.port,
                      sp_secret="sp-1", ca_file="/nonexistent/ca.crt")


if __name__ == "__main__":
    unittest.main()
