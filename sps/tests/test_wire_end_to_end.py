"""Wire end-to-end: TLS/TCP server with real server cert, real client, real round trip."""
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from dataclasses import make_dataclass
from pathlib import Path

from sps.config import Config
from sps.handlers import HandlerContext
from sps.server import build_server
from sps.store import ToolRegistrationStore


def _gen_self_signed(tmpdir: Path, name: str = "cert") -> tuple[str, str]:
    cert = tmpdir / f"{name}.crt"
    key = tmpdir / f"{name}.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName = IP:127.0.0.1,DNS:localhost",
    ], check=True, capture_output=True)
    return str(cert), str(key)


def _tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


class _FakePlugin:
    def get_secret(self, field, item):
        if field == "API_KEY":
            return "V"
        raise KeyError(field)

    def write_secret(self, field, item, value):
        pass


class _FakeAudit:
    def __init__(self):
        self.events: list[tuple[str, str, str]] = []

    def event(self, action, *, tool_id="", secret_name=""):
        self.events.append((action, tool_id, secret_name))


def _open_client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(port: int, msg: dict) -> dict:
    raw = json.dumps(msg).encode() + b"\n"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        ss = _open_client_ssl_context().wrap_socket(s, server_hostname="127.0.0.1")
        ss.sendall(raw)
        f = ss.makefile("r")
        resp = f.readline().strip()
        ss.close()
        return json.loads(resp)


class Wire(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)
        self.cert, self.key = _gen_self_signed(self.tmp)
        self.audit = _FakeAudit()
        self.store = ToolRegistrationStore()
        self.plugin = _FakePlugin()
        cfg = Config(
            sp_host="127.0.0.1", sp_port=0, sp_secret="sp-1",
            sp_tls_cert=self.cert, sp_tls_key=self.key, sp_tls_ca="ignored",
            sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
            infisical=None, vault=None, localfile=None,
        )
        AppCtx = make_dataclass("AppCtx", ["config", "store", "audit", "plugin"])
        ctx = AppCtx(config=cfg, store=self.store, audit=self.audit, plugin=self.plugin)
        server = build_server(ctx, host="127.0.0.1", port=0,
                              ssl_ctx=_tls_context(self.cert, self.key))
        self.port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 5)

    def test_register_then_get_secrets_round_trip(self):
        esecret = "e" + "1" * 63
        reg = _send(self.port, {
            "op": "register", "spsecret": "sp-1", "toolid": "echo",
            "esecret": esecret,
            "secrets": [{"name": "api_key", "field": "API_KEY",
                         "item": "echo", "writable": False}],
        })
        self.assertEqual(reg, {"status": "ok"})

        bulk = _send(self.port, {"op": "get_secrets", "toolid": "echo", "esecret": esecret})
        self.assertEqual(bulk, {"status": "ok", "secrets": {"api_key": "V"}})

    def test_unknown_op_returns_bad_request(self):
        resp = _send(self.port, {"op": "frobnicate", "spsecret": "sp-1", "toolid": "echo"})
        self.assertEqual(resp, {"status": "error", "message": "Bad request"})

    def test_wrong_sp_returns_unauthorized(self):
        resp = _send(self.port, {"op": "register", "spsecret": "wrong",
                                  "toolid": "echo", "esecret": "e" + "1" * 63,
                                  "secrets": []})
        self.assertEqual(resp, {"status": "error", "message": "Unauthorized"})

    def test_audit_emits_for_read_and_update(self):
        esecret = "e" + "1" * 63
        _send(self.port, {
            "op": "register", "spsecret": "sp-1", "toolid": "echo",
            "esecret": esecret,
            "secrets": [{"name": "api_key", "field": "API_KEY",
                         "item": "echo", "writable": True}],
        })
        _send(self.port, {"op": "get_secrets", "toolid": "echo", "esecret": esecret})
        _send(self.port, {"op": "write_secret", "toolid": "echo", "esecret": esecret,
                          "name": "api_key", "value": "new"})
        actions = [e[0] for e in self.audit.events]
        self.assertIn("register", actions)
        self.assertIn("get_secrets", actions)
        self.assertIn("write_secret", actions)


if __name__ == "__main__":
    unittest.main()
