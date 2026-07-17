"""handlers: register / unregister op shape + auth envelope."""
import json
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
    handle_get_secret,
    handle_get_secrets,
    handle_register,
    handle_unregister,
    handle_write_secret,
    BadRegistration,
)
from sps.store import Registration, ToolRegistrationStore


class _FakeAudit:
    def __init__(self):
        self.events: list[tuple[str, str, str]] = []

    def event(self, action, *, tool_id="", secret_name=""):
        self.events.append((action, tool_id, secret_name))


def _ctx(sp_secret="sp-1", store=None, plugin=None, audit=None) -> HandlerContext:
    return HandlerContext(
        config=Config(
            sp_host="h", sp_port=1, sp_secret=sp_secret,
            sp_tls_cert="c", sp_tls_key="k", sp_tls_ca="a",
            sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
            infisical=None, vault=None, localfile=None,
        ),
        store=store or ToolRegistrationStore(),
        audit=audit or _FakeAudit(),
        plugin=plugin or mock.Mock(),
    )


def _reg_msg(esecret="e" + "1" * 63, secrets=None, spsecret="sp-1"):
    return {
        "op": "register",
        "spsecret": spsecret,
        "toolid": "echo",
        "esecret": esecret,
        "secrets": secrets if secrets is not None else [
            {"name": "api_key", "field": "API_KEY", "item": "echo", "writable": False}
        ],
    }


class Register(unittest.TestCase):
    def test_register_success(self):
        store = ToolRegistrationStore()
        audit = _FakeAudit()
        ctx = _ctx(store=store, audit=audit)
        resp = handle_register(ctx, _reg_msg())
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(store.get("echo").esecret, "e" + "1" * 63)  # type: ignore[union-attr]
        self.assertIn(("register", "echo", ""), audit.events)

    def test_register_requires_sp_auth(self):
        ctx = _ctx()
        msg = _reg_msg()
        msg["spsecret"] = "ES::" + msg["esecret"]  # wrong prefix value
        with self.assertRaises(AuthError):
            handle_register(ctx, msg)

    def test_register_rejects_wrong_secret(self):
        ctx = _ctx()
        msg = _reg_msg(spsecret="wrong")
        with self.assertRaises(AuthError):
            handle_register(ctx, msg)

    def test_register_defaults_missing_item_and_writable(self):
        store = ToolRegistrationStore()
        ctx = _ctx(store=store)
        msg = {
            "op": "register", "spsecret": "sp-1", "toolid": "echo",
            "esecret": "e" + "1" * 63,
            "secrets": [{"name": "api_key", "field": "API_KEY"}],
        }
        handle_register(ctx, msg)
        entry = store.get("echo").secret_entries[0]  # type: ignore[union-attr]
        self.assertIsNone(entry["item"])
        self.assertEqual(entry["writable"], False)

    def test_register_rejects_malformed_body(self):
        ctx = _ctx()
        with self.assertRaises(BadRegistration):
            handle_register(ctx, {"op": "register", "spsecret": "sp-1", "toolid": "echo",
                                   "esecret": "e" + "1" * 63, "secrets": "not-a-list"})

    def test_register_rejects_missing_esecret(self):
        ctx = _ctx()
        msg = _reg_msg()
        del msg["esecret"]
        with self.assertRaises(BadRegistration):
            handle_register(ctx, msg)

    def test_register_rejects_non_hex_esecret(self):
        ctx = _ctx()
        msg = _reg_msg(esecret="not-hex-zzz")
        with self.assertRaises(BadRegistration):
            handle_register(ctx, msg)

    def test_register_rejects_short_esecret(self):
        ctx = _ctx()
        with self.assertRaises(BadRegistration):
            handle_register(ctx, _reg_msg(esecret="abcd"))

    def test_reregister_overwrites_and_audits(self):
        store = ToolRegistrationStore()
        audit = _FakeAudit()
        ctx = _ctx(store=store, audit=audit)
        handle_register(ctx, _reg_msg(esecret="a" * 64))
        handle_register(ctx, _reg_msg(esecret="b" * 64))
        self.assertEqual(store.get("echo").esecret, "b" * 64)  # type: ignore[union-attr]
        self.assertEqual(sum(1 for e in audit.events if e[0] == "register"), 2)


class Unregister(unittest.TestCase):
    def test_unregister_drops_and_audits(self):
        store = ToolRegistrationStore()
        audit = _FakeAudit()
        ctx = _ctx(store=store, audit=audit)
        handle_register(ctx, _reg_msg())
        resp = handle_unregister(ctx, {"op": "unregister", "spsecret": "sp-1", "toolid": "echo"})
        self.assertEqual(resp["status"], "ok")
        self.assertIsNone(store.get("echo"))
        self.assertIn(("unregister", "echo", ""), audit.events)
