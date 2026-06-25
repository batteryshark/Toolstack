"""toolyard.openapi_import: an OpenAPI spec becomes a rest tool whose ops are NAMED (name +
verb + path template). The decisive test is the round-trip: the generated toolyard.toml is read
straight back by the broker's registry as named ToolOps, proving the spec maps 1:1 onto them.
"""

import tomllib
import unittest
from pathlib import Path
from tempfile import mkdtemp

from broker.registry import Registry
from toolyard import openapi_import


SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Graph", "version": "v1.0"},
    "servers": [{"url": "https://graph.microsoft.com/{version}",
                 "variables": {"version": {"default": "v1.0"}}}],
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/me/todo/lists/{list_id}/tasks/{task_id}": {
            "get": {"operationId": "getTask", "summary": "Get a task",
                    "parameters": [{"name": "list_id", "in": "path", "required": True},
                                   {"name": "task_id", "in": "path", "required": True}]},
        },
        "/me/sendMail": {"post": {"operationId": "sendMail", "summary": "Send a message"}},
        "/me/messages": {
            "get": {"operationId": "listMessages",
                    "parameters": [{"name": "$top", "in": "query", "schema": {"type": "integer"}}]},
        },
    },
}


class BuildPieces(unittest.TestCase):
    def test_base_url_fills_server_variables(self):
        self.assertEqual(openapi_import.base_url(SPEC), "https://graph.microsoft.com/v1.0")

    def test_base_url_swagger2_host_basepath(self):
        spec = {"host": "api.example.com", "basePath": "/v2", "schemes": ["https"]}
        self.assertEqual(openapi_import.base_url(spec), "https://api.example.com/v2")

    def test_operations_map_method_path_and_id(self):
        ops = {o["name"]: o for o in openapi_import.build_operations(SPEC)}
        self.assertEqual(ops["getTask"]["verb"], "GET")
        self.assertEqual(ops["getTask"]["path"], "/me/todo/lists/{list_id}/tasks/{task_id}")
        self.assertEqual(ops["sendMail"]["verb"], "POST")
        self.assertEqual({a["name"] for a in ops["getTask"]["args"]}, {"list_id", "task_id"})

    def test_op_name_is_sanitised_and_deduped(self):
        used = set()
        a = openapi_import.op_name("get", "/x", {"operationId": "weird.op name"}, used)
        b = openapi_import.op_name("get", "/x", {"operationId": "weird.op name"}, used)
        self.assertEqual(a, "weird_op_name")         # no dots/spaces (they break tool.op routing)
        self.assertEqual(b, "weird_op_name_2")       # deduped

    def test_op_name_synthesised_without_operation_id(self):
        name = openapi_import.op_name("get", "/me/messages", {}, set())
        self.assertTrue(name and name[0].isalpha())

    def test_auth_scaffolds_bearer_inject_and_secret(self):
        inject, secrets = openapi_import._auth(SPEC)
        self.assertEqual(inject[0]["name"], "Authorization")
        self.assertEqual(inject[0]["value"], "Bearer ${secret:api_token}")
        self.assertEqual(secrets[0]["name"], "api_token")

    def test_parse_spec_bundles_base_url_inject_secrets_and_ops(self):
        # what the admin UI consumes to offer a selectable import
        out = openapi_import.parse_spec(SPEC)
        self.assertEqual(out["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(out["inject"][0]["name"], "Authorization")
        self.assertEqual(out["secrets"][0]["name"], "api_token")
        self.assertEqual({o["name"] for o in out["operations"]},
                         {"getTask", "sendMail", "listMessages"})


class RoundTrip(unittest.TestCase):
    """The generated toml is valid and the broker registry reads it back as named ops."""

    def _registry(self):
        toml_text = openapi_import.build_toolyard_toml(SPEC, tool_id="graph", port=4640)
        # it parses as TOML at all
        self.parsed = tomllib.loads(toml_text)
        root = Path(mkdtemp(prefix="oai-")) / "tools"
        (root / "graph").mkdir(parents=True)
        (root / "graph" / "toolyard.toml").write_text(toml_text)
        return Registry.from_tools_root(root)

    def test_registry_reads_generated_named_ops(self):
        reg = self._registry()
        get_task = reg.lookup("graph", "getTask")
        self.assertIsNotNone(get_task)
        self.assertEqual(get_task.type, "rest")
        self.assertEqual(get_task.verb, "GET")
        self.assertEqual(get_task.path_template, "/me/todo/lists/{list_id}/tasks/{task_id}")
        self.assertEqual(get_task.risk, "read")               # derived from the verb
        send_mail = reg.lookup("graph", "sendMail")
        self.assertEqual(send_mail.verb, "POST")
        self.assertEqual(send_mail.risk, "write")

    def test_generated_proxy_block_has_base_url_and_inject(self):
        self._registry()
        self.assertEqual(self.parsed["proxy"]["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(self.parsed["proxy"]["inject"][0]["name"], "Authorization")
        self.assertEqual(self.parsed["secrets"][0]["name"], "api_token")


if __name__ == "__main__":
    unittest.main()
