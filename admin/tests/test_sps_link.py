"""SPSLink: readiness gating and restart detection over the ping op."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admin.sps_link import SPSLink
from sps.client import SPSError


class SPSLinkTests(unittest.TestCase):
    def test_constructor_accepts_positional_args(self):
        link = SPSLink("h", 8743, "/ca")
        self.assertEqual(link.host, "h")
        self.assertEqual(link.port, 8743)
        self.assertEqual(link.ca_file, "/ca")
        self.assertTrue(link.verify)

    def test_from_env_returns_none_when_skip_set(self):
        with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_SKIP": "1"}, clear=False):
            self.assertIsNone(SPSLink.from_env("/nonexistent"))

    def test_from_env_returns_none_when_file_missing(self):
        self.assertIsNone(SPSLink.from_env("/nonexistent/sps.env"))

    def test_from_env_parses_config(self):
        tmp = Path(tempfile.mkdtemp(prefix="spslink-"))
        self.addCleanup(__import__("shutil").rmtree, tmp, ignore_errors=True)
        env = tmp / "sps.env"
        env.write_text(
            'SP_HOST = "127.0.0.1"\nSP_PORT = "8743"\nSP_SECRET = "s"\n'
            'SP_TLS_CA = "/tmp/ca.crt"\nSP_PLUGIN = "localfile"\n',
            encoding="utf-8",
        )
        os.chmod(env, 0o600)
        link = SPSLink.from_env(str(env))
        self.assertIsNotNone(link)
        self.assertEqual(link.host, "127.0.0.1")
        self.assertEqual(link.port, 8743)

    def test_from_env_bad_port_returns_none(self):
        tmp = Path(tempfile.mkdtemp(prefix="spslink-"))
        self.addCleanup(__import__("shutil").rmtree, tmp, ignore_errors=True)
        env = tmp / "sps.env"
        env.write_text(
            'SP_HOST = "127.0.0.1"\nSP_PORT = "8743"\nSP_SECRET = "s"\n'
            'SP_TLS_CA = "/tmp/ca.crt"\nSP_PLUGIN = "localfile"\n',
            encoding="utf-8",
        )
        os.chmod(env, 0o600)
        with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_PORT": "not-a-port"}):
            self.assertIsNone(SPSLink.from_env(str(env)))

    def test_from_env_missing_plugin_block_key_returns_none(self):
        tmp = Path(tempfile.mkdtemp(prefix="spslink-"))
        self.addCleanup(__import__("shutil").rmtree, tmp, ignore_errors=True)
        env = tmp / "sps.env"
        env.write_text(
            'SP_HOST = "127.0.0.1"\nSP_PORT = "8743"\nSP_SECRET = "s"\n'
            'SP_TLS_CA = "/tmp/ca.crt"\nSP_PLUGIN = "localfile"\n'
            '[localfile]\n',  # missing VAULT_FILE -> KeyError inside load_config
            encoding="utf-8",
        )
        os.chmod(env, 0o600)
        self.assertIsNone(SPSLink.from_env(str(env)))

    def test_wait_until_up_retries_then_succeeds(self):
        link = SPSLink(host="h", port=1, ca_file=None, verify=False)
        calls = {"n": 0}
        def boot_id(**kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("refused")
            return "up"
        with mock.patch.object(link, "boot_id", side_effect=boot_id):
            self.assertTrue(link.wait_until_up(timeout=2.0, interval=0.0))
        self.assertEqual(calls["n"], 3)

    def test_wait_until_up_times_out(self):
        link = SPSLink(host="h", port=1, ca_file=None, verify=False)
        with mock.patch.object(link, "boot_id", side_effect=OSError("refused")):
            self.assertFalse(link.wait_until_up(timeout=0.0, interval=0.0))

    def test_boot_id_returns_ping_value(self):
        link = SPSLink(host="h", port=1, ca_file=None, verify=False)
        with mock.patch("admin.sps_link.SPSClient") as cli_cls:
            cli_cls.return_value.ping.return_value = {"status": "ok", "boot_id": "abc"}
            self.assertEqual(link.boot_id(), "abc")

    def test_boot_id_raises_when_ping_lacks_boot_id(self):
        link = SPSLink(host="h", port=1, ca_file=None, verify=False)
        with mock.patch("admin.sps_link.SPSClient") as cli_cls:
            cli_cls.return_value.ping.return_value = {"status": "ok"}
            with self.assertRaises(SPSError):
                link.boot_id()

    def test_wait_until_up_propagates_unexpected_error(self):
        link = SPSLink(host="h", port=1, ca_file=None, verify=False)
        with mock.patch.object(link, "boot_id", side_effect=TypeError("bug")):
            with self.assertRaises(TypeError):
                link.wait_until_up(timeout=1.0, interval=0.0)


if __name__ == "__main__":
    unittest.main()
