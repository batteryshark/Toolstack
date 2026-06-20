"""admin.broker_config: the run-config round-trips through TOML, builds the broker
environment, keeps its file private, and never exposes the nod token when masked."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from admin import broker_config
from admin.broker_config import BrokerRunConfig


class BrokerConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-cfg-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._prev = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = str(Path(self.tmp, "config"))
        self.addCleanup(self._restore)

    def _restore(self):
        if self._prev is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._prev

    def test_defaults_when_no_file(self):
        cfg = broker_config.load()
        self.assertEqual(cfg.port, 8765)
        self.assertEqual(cfg.rate_limit, 120)

    def test_save_load_roundtrip(self):
        cfg = BrokerRunConfig(
            port=9001, tools_root="/srv/tools", nod_url="http://nod.local",
            nod_token="s3cr3t", approval_ttl=120, rate_limit=0,
        )
        broker_config.save(cfg)
        self.assertEqual(broker_config.load(), cfg)

    def test_config_file_is_private(self):
        broker_config.save(BrokerRunConfig(nod_token="x"))
        self.assertEqual(broker_config.config_file().stat().st_mode & 0o777, 0o600)

    def test_to_env_omits_empty_optionals(self):
        env = BrokerRunConfig().to_env()
        self.assertIn("TOOLSTACK_BROKER_PORT", env)
        self.assertNotIn("TOOLSTACK_NOD_URL", env)
        self.assertNotIn("TOOLSTACK_NOD_TOKEN", env)
        self.assertNotIn("TOOLSTACK_NOD_CHANNEL", env)  # empty -> broker's "default"

    def test_to_env_includes_nod_when_set(self):
        env = BrokerRunConfig(
            nod_url="http://n", nod_token="t", nod_channel="toolserver",
        ).to_env()
        self.assertEqual(env["TOOLSTACK_NOD_URL"], "http://n")
        self.assertEqual(env["TOOLSTACK_NOD_TOKEN"], "t")
        self.assertEqual(env["TOOLSTACK_NOD_CHANNEL"], "toolserver")

    def test_masked_hides_token(self):
        masked = BrokerRunConfig(nod_token="supersecret").masked()
        self.assertEqual(masked["nod_token"], "set")
        self.assertNotIn("supersecret", str(masked))
        self.assertEqual(BrokerRunConfig().masked()["nod_token"], "not set")

    def test_save_escapes_quotes_and_backslashes(self):
        cfg = BrokerRunConfig(tools_root='/has "quotes" \\and slash')
        broker_config.save(cfg)
        self.assertEqual(broker_config.load().tools_root, '/has "quotes" \\and slash')

    def test_tool_dirs_roundtrip_and_env(self):
        cfg = BrokerRunConfig(tool_dirs=["/srv/a", "/srv/b"])
        broker_config.save(cfg)
        self.assertEqual(broker_config.load().tool_dirs, ["/srv/a", "/srv/b"])
        env = cfg.to_env()
        self.assertEqual(env["TOOLSTACK_TOOLS_DIRS"], os.pathsep.join(["/srv/a", "/srv/b"]))

    def test_empty_tool_dirs_omitted_from_env(self):
        self.assertNotIn("TOOLSTACK_TOOLS_DIRS", BrokerRunConfig().to_env())


class AdminHost(unittest.TestCase):
    """The admin binds loopback by default; TOOLSTACK_ADMIN_HOST overrides it (only the
    in-container case should), mirroring the broker's TOOLSTACK_BROKER_HOST."""

    def test_defaults_to_loopback(self):
        from unittest import mock
        from admin import settings
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TOOLSTACK_ADMIN_HOST", None)
            self.assertEqual(settings.admin_host(), "127.0.0.1")

    def test_nonloopback_fails_closed(self):
        from unittest import mock
        from admin import settings
        with mock.patch.dict(os.environ, {"TOOLSTACK_ADMIN_HOST": "0.0.0.0"}):
            os.environ.pop("TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK", None)
            with self.assertRaises(SystemExit):  # exposes the panel; refuse without the opt-in
                settings.admin_host()

    def test_nonloopback_allowed_with_optin(self):
        from unittest import mock
        from admin import settings
        with mock.patch.dict(os.environ, {"TOOLSTACK_ADMIN_HOST": "0.0.0.0",
                                          "TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK": "1"}):
            self.assertEqual(settings.admin_host(), "0.0.0.0")


class ValidateNodUrl(unittest.TestCase):
    """nod_url carries the nod token outward, so the config surface guards it (SSRF / exfil)."""

    def test_allows_https_loopback_http_and_empty(self):
        from admin import broker_config
        broker_config.validate_nod_url("")                       # no approval surface
        broker_config.validate_nod_url("https://nod.example.com")
        broker_config.validate_nod_url("http://127.0.0.1:8080")  # loopback http ok for dev
        broker_config.validate_nod_url("http://localhost:8080")

    def test_rejects_plain_http_to_remote(self):
        from admin import broker_config
        with self.assertRaises(ValueError):
            broker_config.validate_nod_url("http://nod.example.com")

    def test_rejects_metadata_and_link_local(self):
        from admin import broker_config
        for url in ("https://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/", "https://[fe80::1]/",
                    "https://2852039166/"):  # decimal spelling of 169.254.169.254
            with self.assertRaises(ValueError):
                broker_config.validate_nod_url(url)

    def test_rejects_non_http_scheme(self):
        from admin import broker_config
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://host/"):
            with self.assertRaises(ValueError):
                broker_config.validate_nod_url(url)


if __name__ == "__main__":
    unittest.main()
