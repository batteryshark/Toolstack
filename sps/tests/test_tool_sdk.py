"""tool_sdk: SecretClient + cache + refresh + writeback."""
import os
import unittest
from unittest import mock

from sps.tool_sdk import SecretClient


class FromEnv(unittest.TestCase):
    def setUp(self):
        os.environ["TOOLSTACK_E_SECRET"] = "es-1"
        os.environ["TOOLSTACK_SPS_HOST"] = "127.0.0.1"
        os.environ["TOOLSTACK_SPS_PORT"] = "8743"
        os.environ["TOOLSTACK_SPS_CA"] = "/tmp/ca.crt"

    def tearDown(self):
        for k in (
            "TOOLSTACK_E_SECRET", "TOOLSTACK_SPS_HOST",
            "TOOLSTACK_SPS_PORT", "TOOLSTACK_SPS_CA",
            "TOOLSTACK_SPS_VERIFY",
        ):
            os.environ.pop(k, None)

    def test_from_env_populates_cache(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.return_value = {
                "status": "ok", "secrets": {"api_key": "V1", "other": "V2"},
            }
            c = SecretClient.from_env("echo")
        self.assertEqual(c.get("api_key"), "V1")
        self.assertEqual(c.get("other"), "V2")

    def test_get_unknown_raises_keyerror(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.return_value = {
                "status": "ok", "secrets": {"api_key": "V1"},
            }
            c = SecretClient.from_env("echo")
        with self.assertRaises(KeyError):
            c.get("missing")

    def test_refresh_one(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.return_value = {
                "status": "ok", "secrets": {"a": "1", "b": "2"},
            }
            c = SecretClient.from_env("echo")
            cli.return_value.get_secret.return_value = {
                "status": "ok", "secrets": {"a": "1-new"},
            }
            c.refresh("a")
        self.assertEqual(c.get("a"), "1-new")
        self.assertEqual(c.get("b"), "2")

    def test_refresh_all(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.side_effect = [
                {"status": "ok", "secrets": {"a": "1"}},
                {"status": "ok", "secrets": {"a": "1-new", "b": "2-new"}},
            ]
            c = SecretClient.from_env("echo")
            c.refresh_all()
        self.assertEqual(c.get("a"), "1-new")
        self.assertEqual(c.get("b"), "2-new")

    def test_writeback_updates_cache(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.return_value = {
                "status": "ok", "secrets": {"a": "1"},
            }
            c = SecretClient.from_env("echo")
            c.writeback("a", "1-new")
        cli.return_value.write_secret.assert_called_once_with("echo", "a", "1-new")
        self.assertEqual(c.get("a"), "1-new")

    def test_from_env_requires_e_secret(self):
        os.environ.pop("TOOLSTACK_E_SECRET")
        with self.assertRaises(RuntimeError):
            SecretClient.from_env("echo")


class CacheGet(unittest.TestCase):
    def setUp(self):
        os.environ["TOOLSTACK_E_SECRET"] = "es-1"

    def tearDown(self):
        os.environ.pop("TOOLSTACK_E_SECRET", None)
        os.environ.pop("TOOLSTACK_SPS_VERIFY", None)

    def test_cache_get_returns_none_for_missing(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.return_value = {
                "status": "ok", "secrets": {"a": "1"},
            }
            c = SecretClient.from_env("echo")
        self.assertEqual(c.cache_get("missing"), None)
        self.assertEqual(c.cache_get("a"), "1")


class Names(unittest.TestCase):
    def setUp(self):
        os.environ["TOOLSTACK_E_SECRET"] = "es-1"

    def tearDown(self):
        os.environ.pop("TOOLSTACK_E_SECRET", None)

    def test_names_lists_registered_secrets(self):
        with mock.patch("sps.tool_sdk.SPSClient") as cli:
            cli.return_value.get_secrets.return_value = {
                "status": "ok", "secrets": {"a": "1", "b": "2", "c": "3"},
            }
            c = SecretClient.from_env("echo")
        self.assertEqual(sorted(c.names()), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
