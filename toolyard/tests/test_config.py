"""toolyard.toml parsing."""

import shutil
import tempfile
import unittest
from pathlib import Path

from toolyard.config import discover, load

REPO = Path(__file__).resolve().parents[2]
TOOL_TOML = REPO / "tools" / "echo_rest" / "toolyard.toml"


class Load(unittest.TestCase):
    def test_parses_echo_tool(self):
        tool = load(TOOL_TOML)
        self.assertEqual(tool.id, "echo")
        self.assertEqual(tool.type, "rest")
        self.assertEqual(tool.port, 4601)
        self.assertEqual(tool.command, "python3 app.py")
        self.assertEqual({s.name for s in tool.secrets}, {"api_key"})
        self.assertEqual(tool.secrets[0].field, "API_KEY")

    def test_discover_finds_echo(self):
        ids = {d.id for d in discover(REPO / "tools")}
        self.assertIn("echo", ids)

    def test_secret_vault_item_default_to_none(self):
        # The echo tool declares no vault/item, so they parse as None.
        spec = load(TOOL_TOML).secrets[0]
        self.assertIsNone(spec.vault)
        self.assertIsNone(spec.item)


class PortValidation(unittest.TestCase):
    """A rest tool with no/invalid port must fail at load() — not reach the runner as
    TOOLSTACK_PORT='None' / `-p 127.0.0.1:None:None`. Parallel to the broker's registry
    check (broker/tests/test_registry.py::PortValidation)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, toml: str) -> Path:
        p = Path(self.tmp, "toolyard.toml")
        p.write_text(toml)
        return p

    def test_missing_port_raises_naming_the_tool(self):
        with self.assertRaises(ValueError) as cm:
            load(self._write('id = "weather"\ntype = "rest"\n[entrypoint]\ncommand = "x"\n'))
        msg = str(cm.exception)
        self.assertIn("weather", msg)
        self.assertIn("port", msg)

    def test_non_integer_port_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "weather"\ntype = "rest"\n[entrypoint]\nport = "4601"\n'))

    def test_boolean_port_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "weather"\ntype = "rest"\n[entrypoint]\nport = true\n'))

    def test_out_of_range_port_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "weather"\ntype = "rest"\n[entrypoint]\nport = 0\n'))

    def test_valid_port_loads(self):
        tool = load(self._write(
            'id = "weather"\ntype = "rest"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))
        self.assertEqual(tool.port, 4700)


if __name__ == "__main__":
    unittest.main()
