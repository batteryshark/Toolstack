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
    "description": "Weather lookups", "port": 4700,
    "operations": [
        {"name": "today", "risk": "read", "description": "Today's weather",
         "args": [{"name": "city", "type": "string", "required": True, "description": "city name"}]},
        {"name": "alerts", "risk": "destructive", "description": "", "args": []},
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

    def test_infisical_vault_item_round_trip(self):
        # The Infisical coordinates survive normalize -> to_toml -> parse, so editing an
        # Infisical-backed tool in the panel does not strip its vault/item.
        data = tool_authoring.normalize({**FULL, "secrets": [
            {"name": "api_key", "field": "API_KEY", "vault": "ToolServer",
             "item": "weather-tool", "writable": True}]})
        parsed = tomllib.loads(tool_authoring.to_toml(data))
        sec = parsed["secrets"][0]
        self.assertEqual((sec["vault"], sec["item"], sec["writable"]),
                         ("ToolServer", "weather-tool", True))

    def test_blank_vault_item_are_omitted(self):
        # No vault/item declared -> no keys emitted (so file-backend tools stay clean and
        # the backend defaults apply).
        parsed = tomllib.loads(tool_authoring.to_toml(tool_authoring.normalize(FULL)))
        self.assertNotIn("vault", parsed["secrets"][0])
        self.assertNotIn("item", parsed["secrets"][0])

    def test_escapes_quotes_in_description(self):
        data = tool_authoring.normalize(
            {**FULL, "operations": [{"name": "today", "risk": "read",
                                     "description": 'echoes "quoted" text', "args": []}]})
        parsed = tomllib.loads(tool_authoring.to_toml(data))
        self.assertEqual(parsed["operations"][0]["description"], 'echoes "quoted" text')

    def test_tool_description_round_trips(self):
        parsed = tomllib.loads(tool_authoring.to_toml(tool_authoring.normalize(FULL)))
        self.assertEqual(parsed["description"], "Weather lookups")

    def test_blank_tool_description_omitted(self):
        parsed = tomllib.loads(tool_authoring.to_toml(tool_authoring.normalize({**FULL, "description": ""})))
        self.assertNotIn("description", parsed)

    def test_multiline_description_escaped_not_broken(self):
        # A pasted multi-line description must escape to \n, not emit a literal newline that
        # would make the TOML basic string invalid.
        data = tool_authoring.normalize({**FULL, "description": "line one\nline two"})
        toml_text = tool_authoring.to_toml(data)
        self.assertIn("\\n", toml_text)
        self.assertEqual(tomllib.loads(toml_text)["description"], "line one\nline two")

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

    def test_overlong_id_rejected(self):
        # the id becomes a directory name (tools_root/<id>); cap it well under FS limits
        self.assertTrue(self._errs(id="a" * 100))
        self.assertEqual(self._errs(id="a" * 64), [])  # 64 is allowed

    def test_empty_command_and_image_is_valid_for_docker_build(self):
        # A docker tool builds the Dockerfile in its directory, so it has neither command
        # nor image. validate() (which can't see the directory) must allow that; write()
        # enforces that *some* entrypoint exists.
        self.assertEqual(self._errs(command="", image=""), [])

    def test_bad_port(self):
        self.assertTrue(self._errs(port="nope"))
        self.assertTrue(self._errs(port=0))

    def test_no_operations(self):
        self.assertTrue(self._errs(operations=[]))

    def test_bad_risk(self):
        self.assertTrue(self._errs(operations=[{"name": "x", "risk": "critical", "args": []}]))

    def test_duplicate_operation(self):
        dup = [{"name": "a", "risk": "read", "args": []}, {"name": "a", "risk": "read", "args": []}]
        self.assertTrue(any("duplicate" in e for e in self._errs(operations=dup)))


class ReadWrite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-author-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_write_then_read_roundtrip(self):
        tool_authoring.write(self.tmp, tool_authoring.normalize(FULL))
        again = tool_authoring.read(self.tmp)
        self.assertEqual(again["id"], "weather")
        self.assertEqual(again["description"], "Weather lookups")
        self.assertEqual(len(again["operations"]), 2)
        self.assertEqual(again["operations"][0]["args"][0]["name"], "city")
        self.assertEqual(again["secrets"][0]["field"], "API_KEY")

    def test_written_file_is_consumable_by_broker_and_toolyard(self):
        tool_authoring.write(self.tmp, tool_authoring.normalize(FULL))
        reg = Registry.from_sources(None, [self.tmp])
        self.assertEqual(reg.lookup("weather", "today").port, 4700)
        td = load_tool(Path(self.tmp, "toolyard.toml"))
        self.assertEqual(td.id, "weather")
        self.assertEqual(td.description, "Weather lookups")
        self.assertEqual(td.secrets[0].field, "API_KEY")

    def test_write_invalid_raises(self):
        with self.assertRaises(ValueError):
            tool_authoring.write(self.tmp, tool_authoring.normalize({**FULL, "id": "bad.id"}))

    def test_write_missing_dir_raises(self):
        with self.assertRaises(ValueError):
            tool_authoring.write(Path(self.tmp, "nope"), tool_authoring.normalize(FULL))

    def test_docker_build_tool_requires_a_dockerfile(self):
        # No command, no image, no Dockerfile -> write() refuses (nothing to run).
        no_entry = tool_authoring.normalize({**FULL, "command": "", "image": ""})
        with self.assertRaises(ValueError):
            tool_authoring.write(self.tmp, no_entry)
        # Add a Dockerfile and it writes — this is the real docker tools' shape (e.g. sandals).
        Path(self.tmp, "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        tool_authoring.write(self.tmp, no_entry)
        self.assertEqual(tool_authoring.read(self.tmp)["id"], "weather")

    def test_read_write_destructive_risks_are_valid(self):
        # The taxonomy the real tools use must survive validate (the bug: only low/medium/high
        # were accepted, so editing sandals — all 'read' ops — 400'd).
        ops = [{"name": "a", "risk": "read", "args": []},
               {"name": "b", "risk": "write", "args": []},
               {"name": "c", "risk": "destructive", "args": []}]
        self.assertEqual(tool_authoring.validate(tool_authoring.normalize({**FULL, "operations": ops})), [])


if __name__ == "__main__":
    unittest.main()
