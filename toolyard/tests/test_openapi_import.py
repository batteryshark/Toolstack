"""toolyard.openapi_import: OpenAPI specs become current-contract REST tools."""

import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from broker.registry import Registry
from toolstack_forwarder.config import load_config as load_rest_config
from toolyard import openapi_import


SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Graph", "version": "v1.0"},
    "servers": [{"url": "https://graph.microsoft.com/{version}",
                 "variables": {"version": {"default": "v1.0"}}}],
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/me/messages": {
            "get": {"operationId": "listMessages",
                    "parameters": [{"name": "$top", "in": "query", "schema": {"type": "integer"}}]},
        },
        "/me/sendMail": {
            "post": {"operationId": "sendMail", "summary": "Send a message",
                     "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}},
        },
        "/me/todo/lists/{list_id}/tasks/{task_id}": {
            "get": {"operationId": "getTask", "summary": "Get a task",
                    "parameters": [{"name": "list_id", "in": "path", "required": True},
                                   {"name": "task_id", "in": "path", "required": True}]},
        },
    },
}


class BuildPieces(unittest.TestCase):
    def test_base_url_fills_server_variables(self):
        self.assertEqual(openapi_import.base_url(SPEC), "https://graph.microsoft.com/v1.0")

    def test_base_url_swagger2_host_basepath(self):
        spec = {"host": "api.example.com", "basePath": "/v2", "schemes": ["https"]}
        self.assertEqual(openapi_import.base_url(spec), "https://api.example.com/v2")

    def test_op_name_is_sanitised_and_deduped(self):
        used = set()
        a = openapi_import.op_name("get", "/x", {"operationId": "weird.op name"}, used)
        b = openapi_import.op_name("get", "/x", {"operationId": "weird.op name"}, used)
        self.assertEqual(a, "weird_op_name")
        self.assertEqual(b, "weird_op_name_2")

    def test_parse_spec_returns_forwarder_pieces(self):
        out = openapi_import.parse_spec(SPEC)
        self.assertEqual(out["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertEqual(out["auth_headers"][0]["value"], "Bearer {{secret:api_token}}")
        self.assertEqual(out["secrets"][0]["name"], "api_token")
        ops = {o["name"]: o for o in out["operations"]}
        self.assertEqual(ops["getTask"]["verb"], "GET")
        self.assertEqual(ops["getTask"]["path"], "/me/todo/lists/{list_id}/tasks/{task_id}")
        self.assertEqual(ops["getTask"]["args"][0]["name"], "variables")
        self.assertEqual(ops["sendMail"]["body_kind"], "text")
        self.assertEqual(ops["sendMail"]["body_content_type"], "application/json")
        self.assertNotIn("$top", {a["name"] for a in ops["listMessages"]["args"]})


class RoundTrip(unittest.TestCase):
    def _write_generated(self):
        toml_text = openapi_import.build_toolyard_toml(SPEC, tool_id="graph", port=4640)
        parsed = tomllib.loads(toml_text)
        tmp = TemporaryDirectory(prefix="oai-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "tools"
        tool_dir = root / "graph"
        tool_dir.mkdir(parents=True)
        (tool_dir / "toolyard.toml").write_text(toml_text, encoding="utf-8")
        return parsed, tool_dir

    def test_generated_toml_uses_forwarder_contract(self):
        parsed, _ = self._write_generated()
        self.assertEqual(parsed["type"], "rest")
        self.assertEqual(parsed["base_url"], "https://graph.microsoft.com/v1.0")
        self.assertNotIn("proxy", parsed)
        self.assertEqual(parsed["entrypoint"]["command"], "python3 -m toolstack_forwarder")
        self.assertEqual(parsed["secrets"][0]["name"], "api_token")

    def test_generated_tool_loads_in_registry_and_forwarder(self):
        _, tool_dir = self._write_generated()
        reg = Registry.from_tools_root(tool_dir.parent)
        get_task = reg.lookup("graph", "getTask")
        self.assertEqual((get_task.type, get_task.verb, get_task.path_template, get_task.risk),
                         ("rest", "GET", "/me/todo/lists/{list_id}/tasks/{task_id}", "read"))
        send_mail = reg.lookup("graph", "sendMail")
        self.assertEqual((send_mail.verb, send_mail.body_kind, send_mail.risk), ("POST", "text", "write"))
        cfg = load_rest_config(tool_dir / "toolyard.toml")
        self.assertEqual(cfg.operations["sendMail"].body_content_type, "application/json")


if __name__ == "__main__":
    unittest.main()
