"""SPS ping op: a secret-free liveness/identity probe."""
import unittest
from unittest import mock

from sps.client import SPSClient
from sps.config import Config
from sps.handlers import HandlerContext, handle_ping
from sps.server import _HANDLER_BY_OP
from sps.store import ToolRegistrationStore


class _FakeAudit:
    def event(self, *a, **k):
        pass


def _ctx(boot_id="deadbeef"):
    return HandlerContext(
        config=Config(sp_host="h", sp_port=1, sp_secret="sp-1",
                      sp_tls_cert="c", sp_tls_key="k", sp_tls_ca="a",
                      sp_audit_log="/tmp/x", sp_plugin="infisical",
                      infisical=None, vault=None, localfile=None),
        store=ToolRegistrationStore(), audit=_FakeAudit(), plugin=mock.Mock(),
        boot_id=boot_id,
    )


class Ping(unittest.TestCase):
    def test_ping_returns_boot_id_without_auth(self):
        resp = handle_ping(_ctx("abc123"), {"op": "ping"})
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["boot_id"], "abc123")
        self.assertIsInstance(resp["pid"], int)

    def test_ping_op_is_registered_in_dispatch(self):
        self.assertIs(_HANDLER_BY_OP["ping"], handle_ping)

    def test_client_ping_sends_ping_op(self):
        c = SPSClient("127.0.0.1", 1)
        with mock.patch.object(c, "_call",
                               return_value={"status": "ok", "boot_id": "x"}) as call:
            self.assertEqual(c.ping()["boot_id"], "x")
            call.assert_called_once_with({"op": "ping"})


if __name__ == "__main__":
    unittest.main()
