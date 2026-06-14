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

    def test_to_env_includes_nod_when_set(self):
        env = BrokerRunConfig(nod_url="http://n", nod_token="t", nod_callback_url="http://cb").to_env()
        self.assertEqual(env["TOOLSTACK_NOD_URL"], "http://n")
        self.assertEqual(env["TOOLSTACK_NOD_TOKEN"], "t")
        self.assertEqual(env["TOOLSTACK_NOD_CALLBACK_URL"], "http://cb")

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


if __name__ == "__main__":
    unittest.main()
