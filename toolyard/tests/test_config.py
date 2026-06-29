"""toolyard.toml parsing."""

import shutil
import tempfile
import unittest
from pathlib import Path

from toolyard.config import discover, load

REPO = Path(__file__).resolve().parents[2]
TOOL_TOML = REPO / "tools" / "echo_api" / "toolyard.toml"
TOOL_MCP_TOML = REPO / "tools" / "echo_mcp" / "toolyard.toml"


class Load(unittest.TestCase):
    def test_parses_echo_tool(self):
        tool = load(TOOL_TOML)
        self.assertEqual(tool.id, "echo")
        self.assertEqual(tool.type, "api")
        self.assertEqual(tool.port, 4601)
        self.assertEqual(tool.command, "python3 app.py")
        self.assertEqual(tool.secrets, ())   # the demo tool ships with no secrets

    def test_parses_echo_mcp_tool(self):
        tool = load(TOOL_MCP_TOML)
        self.assertEqual(tool.id, "echo-mcp")
        self.assertEqual(tool.type, "mcp")    # the streamable-HTTP MCP transport
        self.assertEqual(tool.port, 4611)

    def test_discover_finds_all_example_tools(self):
        ids = {d.id for d in discover(REPO / "tools")}
        self.assertIn("echo", ids)
        self.assertIn("echo-mcp", ids)
        self.assertNotIn("kv", ids)


class Secrets(unittest.TestCase):
    """[[secrets]] parsing, against a self-contained fixture (not the shipped demo tool)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _load(self, secrets_toml: str):
        p = Path(self.tmp, "toolyard.toml")
        p.write_text('id = "fix"\ntype = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n\n' + secrets_toml)
        return load(p)

    def test_parses_name_and_field(self):
        spec = self._load('[[secrets]]\nname = "api_key"\nfield = "API_KEY"\n').secrets[0]
        self.assertEqual((spec.name, spec.field), ("api_key", "API_KEY"))

    def test_vault_item_default_to_none(self):
        spec = self._load('[[secrets]]\nname = "api_key"\nfield = "API_KEY"\n').secrets[0]
        self.assertIsNone(spec.vault)
        self.assertIsNone(spec.item)

    def test_description_defaults_empty(self):
        # The echo tool declares no top-level description.
        self.assertEqual(load(TOOL_TOML).description, "")


class Description(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_parses_top_level_description(self):
        p = Path(self.tmp, "toolyard.toml")
        p.write_text('id = "weather"\ntype = "api"\ndescription = "Weather lookups"\n'
                     '[entrypoint]\nport = 4700\ncommand = "x"\n')
        self.assertEqual(load(p).description, "Weather lookups")


class PortValidation(unittest.TestCase):
    """An api or mcp tool with no/invalid port must fail at load(); not reach the runner
    as TOOLSTACK_PORT='None' / `-p 127.0.0.1:None:None`. Parallel to the broker's registry
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
            load(self._write('id = "weather"\ntype = "api"\n[entrypoint]\ncommand = "x"\n'))
        msg = str(cm.exception)
        self.assertIn("weather", msg)
        self.assertIn("port", msg)

    def test_non_integer_port_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "weather"\ntype = "api"\n[entrypoint]\nport = "4601"\n'))

    def test_boolean_port_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "weather"\ntype = "api"\n[entrypoint]\nport = true\n'))

    def test_out_of_range_port_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "weather"\ntype = "api"\n[entrypoint]\nport = 0\n'))

    def test_valid_port_loads(self):
        tool = load(self._write(
            'id = "weather"\ntype = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))
        self.assertEqual(tool.port, 4700)

    def test_mcp_tool_also_needs_a_port(self):
        # an mcp tool is served on a loopback port too, so the same check applies
        with self.assertRaises(ValueError) as cm:
            load(self._write('id = "wx-mcp"\ntype = "mcp"\n[entrypoint]\ncommand = "x"\n'))
        self.assertIn("'mcp'", str(cm.exception))   # message names the actual type

    def test_unknown_type_rejected_even_with_a_valid_port(self):
        # a typo'd type must fail at load, not register silently and mis-dispatch at call time
        with self.assertRaises(ValueError) as cm:
            load(self._write('id = "x"\ntype = "mpc"\n[entrypoint]\nport = 4700\ncommand = "c"\n'))
        self.assertIn("unknown type", str(cm.exception))

    def test_rest_type_rejected(self):
        with self.assertRaises(ValueError) as cm:
            load(self._write('id = "kv"\ntype = "rest"\n[entrypoint]\nport = 4621\ncommand = "c"\n'))
        self.assertIn("unknown type", str(cm.exception))


class IdValidation(unittest.TestCase):
    """A tool id must match the routing charset, and especially carry no dot: the broker splits
    a policy spec on the FIRST dot into (tool, op), so a dotted id silently misroutes policy.
    Reject it at load(). Parallel to the broker's registry check
    (broker/tests/test_registry.py::IdValidation)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, toml: str) -> Path:
        p = Path(self.tmp, "toolyard.toml")
        p.write_text(toml)
        return p

    def test_dotted_id_raises_naming_the_id(self):
        with self.assertRaises(ValueError) as cm:
            load(self._write('id = "my.tool"\ntype = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))
        msg = str(cm.exception)
        self.assertIn("my.tool", msg)
        self.assertIn("id", msg)

    def test_slash_in_id_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('id = "my/tool"\ntype = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))

    def test_missing_id_raises(self):
        with self.assertRaises(ValueError):
            load(self._write('type = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))

    def test_id_with_leading_underscore_raises(self):
        # the charset requires a leading alphanumeric
        with self.assertRaises(ValueError):
            load(self._write('id = "_tool"\ntype = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))

    def test_valid_id_with_dash_and_underscore_loads(self):
        tool = load(self._write(
            'id = "my-cool_tool2"\ntype = "api"\n[entrypoint]\nport = 4700\ncommand = "x"\n'))
        self.assertEqual(tool.id, "my-cool_tool2")


if __name__ == "__main__":
    unittest.main()
