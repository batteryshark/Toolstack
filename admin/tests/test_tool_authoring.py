"""admin.tool_authoring: build / validate / serialize a toolyard.toml, and confirm
the broker's registry and the toolyard's config can read exactly what we wrote."""

import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from admin import tool_authoring
from broker.registry import Registry
from toolyard.config import load as load_tool

FULL = {
    "id": "weather", "type": "rest", "command": "python3 app.py", "image": "",
    "port": 4700,
    "operations": [
        {"name": "today", "risk": "low", "description": "Today's weather",
         "args": [{"name": "city", "type": "string", "required": True, "description": "city name"}]},
        {"name": "alerts", "risk": "high", "description": "", "args": []},
    ],
    "secrets": [{"name": "api_key", "field": "API_KEY", "writable": False}],
}


class Serialize(unittest.TestCase):
    def test_to_toml_parses_back(self):
        parsed = tomllib.loads(tool_authoring.to_toml(tool_authoring.normalize(FULL)))
        self.assertEqual(parsed["id"], "weather")
        self.assertEqual(parsed["entrypoint"]["command"], "python3 app.py")
        self.assertEqual(parsed["entrypoint"]["port"], 4700)
        self.assertEqual(parsed["operations"][0]["name"], "today")
        self.assertEqual(parsed["operations"][0]["args"][0]["name"], "city")
        self.assertTrue(parsed["operations"][0]["args"][0]["required"])
        self.assertEqual(parsed["secrets"][0]["field"], "API_KEY")

    def test_escapes_quotes_in_description(self):
        data = tool_authoring.normalize(
            {**FULL, "operations": [{"name": "today", "risk": "low",
                                     "description": 'echoes "quoted" text', "args": []}]})
        parsed = tomllib.loads(tool_authoring.to_toml(data))
        self.assertEqual(parsed["operations"][0]["description"], 'echoes "quoted" text')

    def test_docker_image_entrypoint(self):
        data = tool_authoring.normalize({**FULL, "command": "", "image": "ghcr.io/x/y:1"})
        parsed = tomllib.loads(tool_authoring.to_toml(data))
        self.assertEqual(parsed["entrypoint"]["image"], "ghcr.io/x/y:1")
        self.assertNotIn("command", parsed["entrypoint"])


class Validate(unittest.TestCase):
    def _errs(self, **over):
        return tool_authoring.validate(tool_authoring.normalize({**FULL, **over}))

    def test_valid(self):
        self.assertEqual(self._errs(), [])

    def test_bad_id_with_dot(self):
        self.assertTrue(self._errs(id="bad.id"))

    def test_missing_entrypoint(self):
        self.assertTrue(self._errs(command="", image=""))

    def test_bad_port(self):
        self.assertTrue(self._errs(port="nope"))
        self.assertTrue(self._errs(port=0))

    def test_no_operations(self):
        self.assertTrue(self._errs(operations=[]))

    def test_bad_risk(self):
        self.assertTrue(self._errs(operations=[{"name": "x", "risk": "critical", "args": []}]))

    def test_duplicate_operation(self):
        dup = [{"name": "a", "risk": "low", "args": []}, {"name": "a", "risk": "low", "args": []}]
        self.assertTrue(any("duplicate" in e for e in self._errs(operations=dup)))


class ReadWrite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-author-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_write_then_read_roundtrip(self):
        tool_authoring.write(self.tmp, tool_authoring.normalize(FULL))
        again = tool_authoring.read(self.tmp)
        self.assertEqual(again["id"], "weather")
        self.assertEqual(len(again["operations"]), 2)
        self.assertEqual(again["operations"][0]["args"][0]["name"], "city")
        self.assertEqual(again["secrets"][0]["field"], "API_KEY")

    def test_written_file_is_consumable_by_broker_and_toolyard(self):
        tool_authoring.write(self.tmp, tool_authoring.normalize(FULL))
        reg = Registry.from_sources(None, [self.tmp])
        self.assertEqual(reg.lookup("weather", "today").port, 4700)
        td = load_tool(Path(self.tmp, "toolyard.toml"))
        self.assertEqual(td.id, "weather")
        self.assertEqual(td.secrets[0].field, "API_KEY")

    def test_write_invalid_raises(self):
        with self.assertRaises(ValueError):
            tool_authoring.write(self.tmp, tool_authoring.normalize({**FULL, "id": "bad.id"}))

    def test_write_missing_dir_raises(self):
        with self.assertRaises(ValueError):
            tool_authoring.write(Path(self.tmp, "nope"), tool_authoring.normalize(FULL))


if __name__ == "__main__":
    unittest.main()
