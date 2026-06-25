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
    "id": "weather", "type": "api", "command": "python3 app.py", "image": "",
    "description": "Weather lookups", "port": 4700,
    "operations": [
        {"name": "today", "risk": "read", "description": "Today's weather",
         "args": [{"name": "city", "type": "string", "required": True, "description": "city name"}]},
        {"name": "alerts", "risk": "destructive", "description": "", "args": []},
    ],
    "secrets": [{"name": "api_key", "field": "API_KEY", "writable": False}],
}

REST_FIXTURE = {
    "id": "kv", "type": "rest", "command": "python3 app.py", "image": "",
    "description": "KV store", "port": 4621,
    "operations": [
        {"name": "get", "risk": "read", "description": "read a key", "args": []},  # lowercased -> GET
        {"name": "DELETE", "risk": "read", "description": "", "args": []},          # wrong risk -> derived
    ],
    "secrets": [],
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

    def test_mcp_type_is_valid(self):
        # mcp is an authorable transport (same entrypoint form, broker calls it over MCP)
        self.assertEqual(self._errs(type="mcp"), [])

    def test_unknown_type_rejected(self):
        self.assertTrue(any("type must be one of" in e for e in self._errs(type="banana")))


class RestAuthoring(unittest.TestCase):
    """A rest tool's ops are HTTP verbs: normalize uppercases them, derives risk from the
    verb, and gives them the fixed {path, body, query} shape; validate rejects non-verbs."""

    def test_normalize_uppercases_verbs_derives_risk_and_sets_args(self):
        norm = tool_authoring.normalize(REST_FIXTURE)
        ops = {o["name"]: o for o in norm["operations"]}
        self.assertEqual(set(ops), {"GET", "DELETE"})            # "get" -> "GET"
        self.assertEqual(ops["GET"]["risk"], "read")
        self.assertEqual(ops["DELETE"]["risk"], "destructive")   # derived, not the "read" we passed
        self.assertEqual([a["name"] for a in ops["GET"]["args"]], ["path", "body", "query", "headers"])

    def test_validate_accepts_verb_ops(self):
        self.assertEqual(tool_authoring.validate(tool_authoring.normalize(REST_FIXTURE)), [])

    def test_validate_rejects_a_non_verb_op(self):
        bad = {**REST_FIXTURE, "operations": [{"name": "frobnicate", "risk": "read", "args": []}]}
        errs = tool_authoring.validate(tool_authoring.normalize(bad))
        self.assertTrue(any("HTTP verb" in e for e in errs))

    def test_written_rest_tool_is_consumable_by_broker_and_toolyard(self):
        tmp = tempfile.mkdtemp(prefix="admin-rest-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool_authoring.write(tmp, tool_authoring.normalize(REST_FIXTURE))
        op = Registry.from_sources(None, [tmp]).lookup("kv", "DELETE")
        self.assertEqual((op.type, op.risk), ("rest", "destructive"))
        self.assertEqual(load_tool(Path(tmp, "toolyard.toml")).type, "rest")


NAMED_REST_FIXTURE = {
    "id": "graph", "type": "rest", "command": "python3 -m toolyard.http_proxy", "image": "",
    "description": "Graph", "port": 4640,
    "operations": [
        {"name": "get_task", "verb": "get",   # lowercase verb -> uppercased
         "path": "/me/todo/lists/{list_id}/tasks/{task_id}", "description": "Get a task",
         "args": [{"name": "list_id", "type": "string", "required": True, "description": "list id"},
                  {"name": "task_id", "type": "string", "required": True, "description": "task id"}]},
        {"name": "GET"},   # a bare-verb passthrough alongside the named op
    ],
    "secrets": [],
}


class NamedRestAuthoring(unittest.TestCase):
    """A rest op may be NAMED (name + verb + path template) instead of a bare verb. normalize keeps
    the verb + path, derives risk from the verb, and the pair round-trips through write/read."""

    def test_normalize_keeps_named_op_and_derives_risk(self):
        ops = {o["name"]: o for o in tool_authoring.normalize(NAMED_REST_FIXTURE)["operations"]}
        self.assertEqual(ops["get_task"]["verb"], "GET")                       # uppercased
        self.assertEqual(ops["get_task"]["path"], "/me/todo/lists/{list_id}/tasks/{task_id}")
        self.assertEqual(ops["get_task"]["risk"], "read")                      # derived from GET
        self.assertEqual([a["name"] for a in ops["get_task"]["args"]], ["list_id", "task_id"])
        self.assertIsNone(ops["GET"].get("path"))                             # passthrough still works

    def test_validate_accepts_named_op(self):
        self.assertEqual(tool_authoring.validate(tool_authoring.normalize(NAMED_REST_FIXTURE)), [])

    def test_validate_rejects_named_op_without_verb(self):
        bad = {**NAMED_REST_FIXTURE, "operations": [{"name": "get_task", "path": "/x/{id}"}]}
        self.assertTrue(any("needs a verb" in e for e in
                            tool_authoring.validate(tool_authoring.normalize(bad))))

    def test_validate_rejects_named_op_with_relative_path(self):
        bad = {**NAMED_REST_FIXTURE,
               "operations": [{"name": "get_task", "verb": "GET", "path": "me/messages"}]}
        self.assertTrue(any("must start with '/'" in e for e in
                            tool_authoring.validate(tool_authoring.normalize(bad))))

    def test_named_op_round_trips_and_broker_reads_it(self):
        tmp = tempfile.mkdtemp(prefix="admin-named-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool_authoring.write(tmp, tool_authoring.normalize(NAMED_REST_FIXTURE))
        op = Registry.from_sources(None, [tmp]).lookup("graph", "get_task")   # broker reads the named op
        self.assertEqual((op.verb, op.path_template, op.risk),
                         ("GET", "/me/todo/lists/{list_id}/tasks/{task_id}", "read"))
        again = {o["name"]: o for o in tool_authoring.read(tmp)["operations"]}  # editor reads it back
        self.assertEqual(again["get_task"]["verb"], "GET")
        self.assertEqual(again["get_task"]["path"], "/me/todo/lists/{list_id}/tasks/{task_id}")
        self.assertEqual([a["name"] for a in again["get_task"]["args"]], ["list_id", "task_id"])


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
            tool_authoring.write(self.tmp, no_entry, runner="docker")
        # Add a Dockerfile and it writes. This is the real docker tools' shape (e.g. sandals).
        Path(self.tmp, "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        tool_authoring.write(self.tmp, no_entry, runner="docker")
        self.assertEqual(tool_authoring.read(self.tmp)["id"], "weather")

    def test_docker_runner_rejects_command_only_tool(self):
        # The echo-mcp bug: a tool with a process command but no image and no Dockerfile
        # validates fine but 502s on first start under the docker runner. write() must catch
        # it at save time (command alone is not a docker entrypoint).
        cmd_only = tool_authoring.normalize(FULL)   # has command, image="", no Dockerfile
        with self.assertRaises(ValueError):
            tool_authoring.write(self.tmp, cmd_only, runner="docker")
        # The same tool is fine under the process runner.
        self.assertEqual(tool_authoring.write(self.tmp, cmd_only, runner="process").name,
                         "toolyard.toml")
        # And a docker tool with an explicit image needs no Dockerfile.
        with_image = tool_authoring.normalize({**FULL, "command": "", "image": "ghcr.io/x/y:1"})
        self.assertEqual(tool_authoring.write(self.tmp, with_image, runner="docker").name,
                         "toolyard.toml")

    def test_read_write_destructive_risks_are_valid(self):
        # The taxonomy the real tools use must survive validate (the bug: only low/medium/high
        # were accepted, so editing sandals (all 'read' ops) 400'd).
        ops = [{"name": "a", "risk": "read", "args": []},
               {"name": "b", "risk": "write", "args": []},
               {"name": "c", "risk": "destructive", "args": []}]
        self.assertEqual(tool_authoring.validate(tool_authoring.normalize({**FULL, "operations": ops})), [])


class BundledSampleTools(unittest.TestCase):
    """Guard against the recurring 'sample shipped without a Dockerfile' redeploy failure
    (echo_mcp, then rest_kv): every tool bundled under <repo>/tools must be startable by the
    docker runner, i.e. carry an `image` or a `Dockerfile` (a process `command` alone won't
    build). Caught here at test time instead of at `redeploy` time."""

    def test_every_bundled_tool_is_docker_startable(self):
        tools_root = Path(__file__).resolve().parents[2] / "tools"
        manifests = sorted(tools_root.glob("*/toolyard.toml"))
        self.assertTrue(manifests, f"no bundled tools found under {tools_root}")
        for manifest in manifests:
            tool_dir = manifest.parent
            with self.subTest(tool=tool_dir.name):
                data = tool_authoring.read(tool_dir)
                self.assertIsNone(
                    tool_authoring.entrypoint_error(data, tool_dir, runner="docker"),
                    f"{tool_dir.name} can't start under the docker runner: add a Dockerfile "
                    f"or set an image in its toolyard.toml")


PROXY_FIXTURE = {
    "id": "graph", "type": "rest", "command": "", "image": "", "port": 4640,
    "description": "Graph proxy",
    "proxy": {
        "base_url": "https://graph.microsoft.com/v1.0",
        "inject": [{"into": "header", "name": "Authorization", "value": "Bearer ${secret:graph_token}"}],
        "forward_headers": ["Prefer", "If-Match"],
        "rotatable": ["graph_token"],
    },
    "operations": [{"name": "get_me", "verb": "GET", "path": "/me", "args": []}, {"name": "GET"}],
    "secrets": [{"name": "graph_token", "field": "GRAPH_TOKEN", "writable": True}],
}


class ProxyAuthoring(unittest.TestCase):
    """A proxied rest tool (external API): the operator fills a [proxy] block; the command is
    auto-set to the bundled http_proxy and the entrypoint check is satisfied without a command."""

    def _bad_proxy(self, **over):
        return {**PROXY_FIXTURE, "proxy": {**PROXY_FIXTURE["proxy"], **over}}

    def test_normalize_autofills_command_and_carries_proxy(self):
        norm = tool_authoring.normalize(PROXY_FIXTURE)
        self.assertEqual(norm["command"], "python3 -m toolyard.http_proxy")
        self.assertEqual(norm["proxy"]["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(norm["proxy"]["inject"][0]["name"], "Authorization")

    def test_validate_accepts_full_proxy(self):
        self.assertEqual(tool_authoring.validate(tool_authoring.normalize(PROXY_FIXTURE)), [])

    def test_entrypoint_satisfied_in_proxy_mode_without_command(self):
        norm = tool_authoring.normalize(PROXY_FIXTURE)
        self.assertIsNone(tool_authoring.entrypoint_error(norm, ".", runner="docker"))  # even docker

    def test_validate_rejects_inject_into_invalid(self):
        bad = self._bad_proxy(inject=[{"into": "cookie", "name": "X", "value": "y"}])
        self.assertTrue(any("header/query/body" in e
                            for e in tool_authoring.validate(tool_authoring.normalize(bad))))

    def test_validate_rejects_inject_secret_without_declaration(self):
        bad = {**PROXY_FIXTURE, "secrets": [], "proxy": {**PROXY_FIXTURE["proxy"], "rotatable": []}}
        self.assertTrue(any("no matching" in e
                            for e in tool_authoring.validate(tool_authoring.normalize(bad))))

    def test_validate_requires_secret_for_base_url_ref(self):
        bad = self._bad_proxy(base_url="https://api.example.com/${secret:tenant}/v1")
        errs = tool_authoring.validate(tool_authoring.normalize(bad))
        self.assertTrue(any("tenant" in e and "no matching" in e for e in errs))

    def test_validate_rejects_reserved_forward_header(self):
        bad = self._bad_proxy(forward_headers=["Authorization"])
        self.assertTrue(any("reserved" in e
                            for e in tool_authoring.validate(tool_authoring.normalize(bad))))

    def test_validate_rejects_rotatable_not_writable(self):
        bad = {**PROXY_FIXTURE, "secrets": [{"name": "graph_token", "field": "GRAPH_TOKEN", "writable": False}]}
        self.assertTrue(any("writable" in e
                            for e in tool_authoring.validate(tool_authoring.normalize(bad))))

    def test_to_toml_emits_proxy_block(self):
        parsed = tomllib.loads(tool_authoring.to_toml(tool_authoring.normalize(PROXY_FIXTURE)))
        self.assertEqual(parsed["proxy"]["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(parsed["proxy"]["inject"][0]["into"], "header")
        self.assertEqual(parsed["proxy"]["forward_headers"], ["Prefer", "If-Match"])
        self.assertEqual(parsed["proxy"]["rotatable"], ["graph_token"])

    def test_written_proxy_tool_round_trips_and_broker_reads_it(self):
        tmp = tempfile.mkdtemp(prefix="admin-proxy-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool_authoring.write(tmp, tool_authoring.normalize(PROXY_FIXTURE))  # entrypoint ok (proxy)
        reg = Registry.from_sources(None, [tmp])
        self.assertEqual(reg.lookup("graph", "get_me").path_template, "/me")  # registry ignores [proxy]
        again = tool_authoring.read(tmp)                                      # editor reads it back
        self.assertEqual(again["proxy"]["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(again["proxy"]["forward_headers"], ["Prefer", "If-Match"])
        self.assertEqual(again["command"], "python3 -m toolyard.http_proxy")


if __name__ == "__main__":
    unittest.main()
