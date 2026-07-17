"""handlers: write_secret op + explicit writable check."""
import unittest
from unittest import mock

from sps.config import Config
from sps.handlers import (
    AuthError,
    BackendError,
    HandlerContext,
    NotWritable,
    SecretNotFound,
    ToolNotFound,
    handle_write_secret,
    BadRegistration,
)
from sps.store import Registration, ToolRegistrationStore


class _FakeAudit:
    def event(self, action, *, tool_id="", secret_name=""):
        pass


class _FakePlugin:
    def __init__(self):
        self.writes: list[tuple[str, str, str]] = []

    def write_secret(self, field, item, value):
        self.writes.append((field, item, value))


ESECRET = "e" + "1" * 63


def _ctx(plugin=None, *, writable=True):
    store = ToolRegistrationStore()
    store.register("echo", Registration(
        esecret=ESECRET,
        secret_entries=(
            {"name": "api_key", "field": "API_KEY",
             "item": "echo", "writable": writable},
        ),
    ))
    return HandlerContext(
        config=Config(
            sp_host="h", sp_port=1, sp_secret="sp-1",
            sp_tls_cert="c", sp_tls_key="k", sp_tls_ca="a",
            sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
            infisical=None, vault=None, localfile=None,
        ),
        store=store, audit=_FakeAudit(), plugin=plugin or _FakePlugin(),
    )


class Write(unittest.TestCase):
    def test_success(self):
        plugin = _FakePlugin()
        ctx = _ctx(plugin)
        resp = handle_write_secret(ctx, {
            "op": "write_secret", "toolid": "echo", "esecret": ESECRET,
            "name": "api_key", "value": "V-rotated",
        })
        self.assertEqual(resp, {"status": "ok", "name": "api_key"})
        self.assertEqual(plugin.writes, [("API_KEY", "echo", "V-rotated")])

    def test_unknown_tool(self):
        ctx = _ctx()
        with self.assertRaises(ToolNotFound):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "nope", "esecret": ESECRET,
                "name": "api_key", "value": "x",
            })

    def test_unknown_secret(self):
        ctx = _ctx()
        with self.assertRaises(SecretNotFound):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "echo", "esecret": ESECRET,
                "name": "missing", "value": "x",
            })

    def test_wrong_auth(self):
        ctx = _ctx()
        with self.assertRaises(AuthError):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "echo", "esecret": "wrong",
                "name": "api_key", "value": "x",
            })

    def test_bad_body(self):
        ctx = _ctx()
        with self.assertRaises(BadRegistration):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "echo", "esecret": ESECRET,
                "name": "api_key",
            })

    def test_missing_value(self):
        ctx = _ctx()
        with self.assertRaises(BadRegistration):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "echo", "esecret": ESECRET,
                "name": "api_key", "value": 12345,  # not a string
            })

    def test_not_writable_returns_typed_error(self):
        # The same call site that drove secret update must NEVER write a
        # non-writable field; the response must signal it via NotWritable so
        # the dispatcher can map to {"status": "error", "message": "Not writable"}.
        ctx = _ctx(writable=False)
        with self.assertRaises(NotWritable):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "echo", "esecret": ESECRET,
                "name": "api_key", "value": "x",
            })

    def test_backend_error_wrapped(self):
        class _BoomPlugin:
            def write_secret(self, field, item, value):
                raise OSError("disk full")
        ctx = _ctx(plugin=_BoomPlugin())
        with self.assertRaises(BackendError):
            handle_write_secret(ctx, {
                "op": "write_secret", "toolid": "echo", "esecret": ESECRET,
                "name": "api_key", "value": "x",
            })
