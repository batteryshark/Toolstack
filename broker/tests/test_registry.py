"""Registry-read: parses toolyard.toml for tool/op/risk/port and stays
physically secret-unaware (never reads the [[secrets]] block)."""

import shutil
import tempfile
import unittest
from pathlib import Path

from broker.registry import Registry

TOML = """
id = "media"
type = "api"

[entrypoint]
port = 4502

[[operations]]
name = "play"
risk = "read"

[[operations]]
name = "skip"
risk = "destructive"

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
        self.assertEqual(op.risk, "destructive")
        self.assertEqual(op.port, 4502)
        self.assertEqual(op.type, "api")

    def test_unknown_op_is_none(self):
        self.assertIsNone(self.registry.lookup("media", "delete"))

    def test_unknown_tool_is_none(self):
        self.assertIsNone(self.registry.lookup("ghost", "go"))

    def test_registry_is_secret_unaware(self):
        blob = repr(self.registry._catalog)
        for forbidden in ("CLIENT_ID", "SUPER_SECRET_VALUE", "client_id", "secrets"):
            self.assertNotIn(forbidden, blob)

    def test_list_ops_carries_tool_type(self):
        # the policy editor shows the transport, so discovery exposes it
        self.assertTrue(self.registry.list_ops())
        self.assertTrue(all(op["type"] == "api" for op in self.registry.list_ops()))


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
            'id = "weather"\ntype = "api"\n[entrypoint]\nport = 4700\n'
            '[[operations]]\nname = "today"\nrisk = "read"\n'
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


class McpType(unittest.TestCase):
    """A type='mcp' tool registers like any other (ops are the policy unit) and its
    ToolOp carries type='mcp' so the runtime routes it over the MCP transport."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        d = Path(self.tmp, "echo-mcp")
        d.mkdir(parents=True)
        (d / "toolyard.toml").write_text(
            'id = "echo-mcp"\ntype = "mcp"\n[entrypoint]\nport = 4611\ncommand = "x"\n'
            '[[operations]]\nname = "say"\nrisk = "read"\n')
        self.registry = Registry.from_tools_root(self.tmp)

    def test_lookup_carries_mcp_type_and_port(self):
        op = self.registry.lookup("echo-mcp", "say")
        self.assertIsNotNone(op)
        self.assertEqual(op.type, "mcp")
        self.assertEqual(op.port, 4611)


class RestType(unittest.TestCase):
    """A type='rest' tool registers named ops with endpoint metadata while the broker
    remains secret-unaware and never stores base_url path/query text."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _load(self, base_url='https://api.example.test/v1?debug=1'):
        d = Path(self.tmp, "kv")
        d.mkdir(parents=True, exist_ok=True)
        (d / "toolyard.toml").write_text(
            f'id = "kv"\ntype = "rest"\nbase_url = "{base_url}"\n[entrypoint]\nport = 4621\n'
            '[[operations]]\nname = "get_item"\nrisk = "read"\nverb = "GET"\npath = "/items/{item_id}"\n'
            'body_kind = "none"\n'
            '[[secrets]]\nname = "api_token"\nfield = "SUPER_SECRET_VALUE"\n'
        )
        return Registry.from_tools_root(self.tmp)

    def test_lookup_carries_rest_metadata_and_strips_base_url_to_host(self):
        op = self._load().lookup("kv", "get_item")
        self.assertIsNotNone(op)
        self.assertEqual(op.type, "rest")
        self.assertEqual(op.verb, "GET")
        self.assertEqual(op.path_template, "/items/{item_id}")
        self.assertEqual(op.base_url_host, "api.example.test")
        self.assertEqual(op.body_kind, "none")

    def test_credentialed_base_url_is_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._load("https://user:pass@api.example.test/v1")
        self.assertIn("credentials", str(cm.exception))

    def test_base_url_host_with_invalid_characters_is_rejected(self):
        with self.assertRaises(ValueError):
            self._load("https://api_example.test/v1")

    def test_registry_is_secret_and_base_url_path_unaware(self):
        reg = self._load("https://api.example.test/tenant/secret-path?debug=1")
        blob = repr(reg._catalog)
        for forbidden in ("SUPER_SECRET_VALUE", "api_token", "tenant", "secret-path", "debug=1"):
            self.assertNotIn(forbidden, blob)


class PortValidation(unittest.TestCase):
    """An api or mcp tool with no/invalid port must fail at load, naming the file + tool;
    not register silently and 502 at call time."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _load(self, toml: str):
        d = Path(self.tmp, "weather")
        d.mkdir(parents=True, exist_ok=True)
        (d / "toolyard.toml").write_text(toml)
        return Registry.from_tools_root(self.tmp)

    def test_missing_port_raises_naming_the_tool(self):
        with self.assertRaises(ValueError) as cm:
            self._load('id = "weather"\ntype = "api"\n[entrypoint]\ncommand = "x"\n'
                       '[[operations]]\nname = "today"\nrisk = "read"\n')
        msg = str(cm.exception)
        self.assertIn("weather", msg)
        self.assertIn("port", msg)

    def test_non_integer_port_raises(self):
        with self.assertRaises(ValueError):
            self._load('id = "weather"\ntype = "api"\n[entrypoint]\nport = "4700"\n'
                       '[[operations]]\nname = "today"\nrisk = "read"\n')

    def test_boolean_port_raises(self):
        # bool is an int subclass; `port = true` must not pass as a port
        with self.assertRaises(ValueError):
            self._load('id = "weather"\ntype = "api"\n[entrypoint]\nport = true\n'
                       '[[operations]]\nname = "today"\nrisk = "read"\n')

    def test_out_of_range_port_raises(self):
        with self.assertRaises(ValueError):
            self._load('id = "weather"\ntype = "api"\n[entrypoint]\nport = 70000\n'
                       '[[operations]]\nname = "today"\nrisk = "read"\n')

    def test_valid_port_loads(self):
        reg = self._load('id = "weather"\ntype = "api"\n[entrypoint]\nport = 4700\n'
                         '[[operations]]\nname = "today"\nrisk = "read"\n')
        self.assertEqual(reg.lookup("weather", "today").port, 4700)

    def test_mcp_tool_also_needs_a_port(self):
        with self.assertRaises(ValueError) as cm:
            self._load('id = "weather"\ntype = "mcp"\n[entrypoint]\ncommand = "x"\n'
                       '[[operations]]\nname = "today"\nrisk = "read"\n')
        self.assertIn("'mcp'", str(cm.exception))   # message names the actual type

    def test_unknown_type_rejected_even_with_a_valid_port(self):
        # a typo'd type must fail at load, not register and mis-dispatch (as api) at call time
        with self.assertRaises(ValueError) as cm:
            self._load('id = "weather"\ntype = "mpc"\n[entrypoint]\nport = 4700\n'
                       '[[operations]]\nname = "today"\nrisk = "read"\n')
        self.assertIn("unknown type", str(cm.exception))

    def test_rest_type_loads_with_valid_port(self):
        reg = self._load('id = "kv"\ntype = "rest"\nbase_url = "https://api.example.test"\n'
                         '[entrypoint]\nport = 4621\n'
                         '[[operations]]\nname = "get_item"\nrisk = "read"\nverb = "GET"\npath = "/items/{id}"\n')
        self.assertEqual(reg.lookup("kv", "get_item").port, 4621)


class IdValidation(unittest.TestCase):
    """A tool id must match the routing charset, and especially carry no dot: a policy spec is
    split on the FIRST dot into (tool, op) (broker/operations.build_policy), so a dotted id like
    'my.tool' would silently misroute its policy. Reject it at load, naming the file + id."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _load(self, toml: str):
        d = Path(self.tmp, "tool")
        d.mkdir(parents=True, exist_ok=True)
        (d / "toolyard.toml").write_text(toml)
        return Registry.from_tools_root(self.tmp)

    def test_dotted_id_raises_naming_the_id(self):
        with self.assertRaises(ValueError) as cm:
            self._load('id = "my.tool"\ntype = "api"\n[entrypoint]\nport = 4700\n'
                       '[[operations]]\nname = "say"\nrisk = "read"\n')
        msg = str(cm.exception)
        self.assertIn("my.tool", msg)
        self.assertIn("id", msg)

    def test_slash_in_id_raises(self):
        with self.assertRaises(ValueError):
            self._load('id = "my/tool"\ntype = "api"\n[entrypoint]\nport = 4700\n'
                       '[[operations]]\nname = "say"\nrisk = "read"\n')

    def test_missing_id_raises(self):
        with self.assertRaises(ValueError):
            self._load('type = "api"\n[entrypoint]\nport = 4700\n'
                       '[[operations]]\nname = "say"\nrisk = "read"\n')

    def test_id_with_leading_dash_raises(self):
        # the charset requires a leading alphanumeric (so an id is never confusable with a flag)
        with self.assertRaises(ValueError):
            self._load('id = "-tool"\ntype = "api"\n[entrypoint]\nport = 4700\n'
                       '[[operations]]\nname = "say"\nrisk = "read"\n')

    def test_valid_id_with_dash_and_underscore_loads(self):
        reg = self._load('id = "my-cool_tool2"\ntype = "api"\n[entrypoint]\nport = 4700\n'
                         '[[operations]]\nname = "say"\nrisk = "read"\n')
        self.assertIsNotNone(reg.lookup("my-cool_tool2", "say"))


if __name__ == "__main__":
    unittest.main()
