"""Registry-read: parses toolyard.toml for tool/op/risk/port and stays
physically secret-unaware (never reads the [[secrets]] block)."""

import shutil
import tempfile
import unittest
from pathlib import Path

from broker.registry import Registry

TOML = """
id = "media"
type = "rest"

[entrypoint]
port = 4502

[[operations]]
name = "play"
risk = "low"

[[operations]]
name = "skip"
risk = "high"

[[secrets]]
name = "client_id"
field = "CLIENT_ID"

[[secrets]]
name = "token"
field = "SUPER_SECRET_VALUE"
"""


class FromToolsRoot(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        tool_dir = Path(self.root) / "media"
        tool_dir.mkdir()
        (tool_dir / "toolyard.toml").write_text(TOML)
        self.registry = Registry.from_tools_root(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_lookup_resolves_op_metadata_and_port(self):
        op = self.registry.lookup("media", "skip")
        self.assertIsNotNone(op)
        self.assertEqual(op.risk, "high")
        self.assertEqual(op.port, 4502)
        self.assertEqual(op.type, "rest")

    def test_unknown_op_is_none(self):
        self.assertIsNone(self.registry.lookup("media", "delete"))

    def test_unknown_tool_is_none(self):
        self.assertIsNone(self.registry.lookup("ghost", "go"))

    def test_registry_is_secret_unaware(self):
        blob = repr(self.registry._catalog)
        for forbidden in ("CLIENT_ID", "SUPER_SECRET_VALUE", "client_id", "secrets"):
            self.assertNotIn(forbidden, blob)


class FromSources(unittest.TestCase):
    """from_sources combines a tools root with explicit per-tool directories
    (tools added through the admin panel, which can live anywhere)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # one tool under a root, one standalone tool dir elsewhere
        root = Path(self.tmp, "root")
        (root / "media").mkdir(parents=True)
        (root / "media" / "toolyard.toml").write_text(TOML)
        self.standalone = Path(self.tmp, "elsewhere", "weather")
        self.standalone.mkdir(parents=True)
        (self.standalone / "toolyard.toml").write_text(
            'id = "weather"\ntype = "rest"\n[entrypoint]\nport = 4700\n'
            '[[operations]]\nname = "today"\nrisk = "low"\n'
        )
        self.root = str(root)

    def test_combines_root_and_tool_dirs(self):
        reg = Registry.from_sources(self.root, [str(self.standalone)])
        self.assertIsNotNone(reg.lookup("media", "play"))      # from the root
        self.assertEqual(reg.lookup("weather", "today").port, 4700)  # from a tool dir

    def test_tool_dir_only(self):
        reg = Registry.from_sources(None, [str(self.standalone)])
        self.assertIsNotNone(reg.lookup("weather", "today"))
        self.assertIsNone(reg.lookup("media", "play"))

    def test_missing_tool_dir_is_skipped(self):
        reg = Registry.from_sources(None, [str(Path(self.tmp, "does-not-exist"))])
        self.assertEqual(reg.list_ops(), [])


if __name__ == "__main__":
    unittest.main()
