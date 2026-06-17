"""toolyard.toml parsing."""

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


if __name__ == "__main__":
    unittest.main()
