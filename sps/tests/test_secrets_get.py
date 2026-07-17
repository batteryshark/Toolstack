"""handlers: get_secrets + get_secret ops."""
import unittest
from unittest import mock

from sps.config import Config
from sps.handlers import (
    AuthError,
    BackendError,
    HandlerContext,
    SecretNotFound,
    ToolNotFound,
    handle_get_secret,
    handle_get_secrets,
)
from sps.store import Registration, ToolRegistrationStore


class _FakeAudit:
    def event(self, action, *, tool_id="", secret_name=""):
        pass


class _FakePlugin:
    def __init__(self, table):
        self.table = table  # (item, field) -> value

    def get_secret(self, field, item):
        v = self.table.get((item, field))
        if v is None:
            raise KeyError(f"{(item, field)}")
        return v


ESECRET = "e" + "1" * 63


def _registered_ctx():
    store = ToolRegistrationStore()
    store.register("echo", Registration(
        esecret=ESECRET,
        secret_entries=(
            {"name": "api_key", "field": "API_KEY", "item": "echo", "writable": False},
            {"name": "other",  "field": "OTHER",  "item": "echo", "writable": False},
        ),
    ))
    plugin = _FakePlugin({("echo", "API_KEY"): "V1", ("echo", "OTHER"): "V2"})
    return HandlerContext(
        config=Config(
            sp_host="h", sp_port=1, sp_secret="sp-1",
            sp_tls_cert="c", sp_tls_key="k", sp_tls_ca="a",
            sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
            infisical=None, vault=None, localfile=None,
        ),
        store=store, audit=_FakeAudit(), plugin=plugin,
    )


class Bulk(unittest.TestCase):
    def test_bulk_success(self):
        ctx = _registered_ctx()
        resp = handle_get_secrets(ctx, {"op": "get_secrets", "toolid": "echo", "esecret": ESECRET})
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["secrets"], {"api_key": "V1", "other": "V2"})

    def test_requires_es_field(self):
        ctx = _registered_ctx()
        with self.assertRaises(AuthError):
            handle_get_secrets(ctx, {"op": "get_secrets", "toolid": "echo"})

    def test_rejects_wrong_es_secret(self):
        ctx = _registered_ctx()
        with self.assertRaises(AuthError):
            handle_get_secrets(ctx, {"op": "get_secrets", "toolid": "echo", "esecret": "nope"})

    def test_unknown_tool(self):
        ctx = _registered_ctx()
        with self.assertRaises(ToolNotFound):
            handle_get_secrets(ctx, {"op": "get_secrets", "toolid": "nope", "esecret": ESECRET})


class Single(unittest.TestCase):
    def test_single_secret_success(self):
        ctx = _registered_ctx()
        resp = handle_get_secret(ctx, {"op": "get_secret", "toolid": "echo",
                                        "esecret": ESECRET, "name": "api_key"})
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["secrets"], {"api_key": "V1"})

    def test_single_secret_unknown_name(self):
        ctx = _registered_ctx()
        with self.assertRaises(SecretNotFound):
            handle_get_secret(ctx, {"op": "get_secret", "toolid": "echo",
                                     "esecret": ESECRET, "name": "missing"})

    def test_backend_error_wrapped(self):
        # Plugin that always raises KeyError -> BackendError.
        ctx = _registered_ctx()
        ctx.plugin = _FakePlugin({})  # empty -> every lookup raises
        with self.assertRaises(BackendError):
            handle_get_secret(ctx, {"op": "get_secret", "toolid": "echo",
                                     "esecret": ESECRET, "name": "api_key"})

    def test_item_falls_back_to_tool_id(self):
        # A CS_TUPLE with item=None should default to toolid.
        store = ToolRegistrationStore()
        store.register("echo", Registration(
            esecret=ESECRET,
            secret_entries=({"name": "api_key", "field": "API_KEY",
                             "item": None, "writable": False},),
        ))
        plugin = _FakePlugin({("echo", "API_KEY"): "VAL"})
        ctx = HandlerContext(
            config=Config(
                sp_host="h", sp_port=1, sp_secret="sp-1",
                sp_tls_cert="c", sp_tls_key="k", sp_tls_ca="a",
                sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
                infisical=None, vault=None, localfile=None,
            ),
            store=store, audit=_FakeAudit(), plugin=plugin,
        )
        resp = handle_get_secret(ctx, {"op": "get_secret", "toolid": "echo",
                                        "esecret": ESECRET, "name": "api_key"})
        self.assertEqual(resp["secrets"]["api_key"], "VAL")
