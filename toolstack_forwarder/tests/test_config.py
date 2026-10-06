import shutil
import tempfile
import unittest
from pathlib import Path

from toolstack_forwarder.config import ConfigError, load_config


BASE = """\
id = "jira"
type = "rest"
description = "Jira Cloud API"
base_url = "https://api.example.test/v1"

[entrypoint]
command = "python3 -m toolstack_forwarder"
port = 4600

[[operations]]
name = "get_user"
risk = "read"
verb = "GET"
path = "/users/{user_id}"
allowed_headers = ["X-Trace"]
"""


class ConfigLoad(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, body: str = BASE) -> Path:
        path = Path(self.tmp, "toolyard.toml")
        path.write_text(body)
        return path

    def test_loads_valid_config_and_defaults_get_to_no_body(self):
        cfg = load_config(self._write())
        self.assertEqual(cfg.tool_id, "jira")
        self.assertEqual(cfg.port, 4600)
        self.assertEqual(cfg.base_url, "https://api.example.test/v1")
        op = cfg.operations["get_user"]
        self.assertEqual(op.verb, "GET")
        self.assertEqual(op.body_kind, "none")
        self.assertIsNone(op.body_content_type)
        self.assertFalse(op.body_substitution)
        self.assertIn("x-trace", op.allowed_headers)
        self.assertFalse(op.redact_response_body)
        self.assertFalse(op.redact_response_headers)

    def test_parses_redaction_flags(self):
        cfg = load_config(self._write(BASE + """
redact_response_body = true
redact_response_headers = true
"""))
        op = cfg.operations["get_user"]
        self.assertTrue(op.redact_response_body)
        self.assertTrue(op.redact_response_headers)

    def test_rejects_non_boolean_redaction_flag(self):
        with self.assertRaises(ConfigError):
            load_config(self._write(BASE + """
redact_response_body = "yes"
"""))

    def test_post_defaults_to_text_json_body(self):
        cfg = load_config(self._write(BASE + """

[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
"""))
        op = cfg.operations["login"]
        self.assertEqual(op.body_kind, "text")
        self.assertEqual(op.body_content_type, "application/json")
        self.assertTrue(op.body_substitution)

    def test_binary_forces_body_substitution_off(self):
        cfg = load_config(self._write(BASE + """

[[operations]]
name = "upload"
risk = "write"
verb = "POST"
path = "/upload/{file_id}"
body_kind = "binary"
body_substitution = true
"""))
        op = cfg.operations["upload"]
        self.assertEqual(op.body_kind, "binary")
        self.assertEqual(op.body_content_type, "application/octet-stream")
        self.assertFalse(op.body_substitution)

    def test_rejects_credentialed_base_url(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(self._write(BASE.replace("https://api.example.test/v1", "https://u:p@example.test")))
        self.assertIn("base_url", str(cm.exception))
        self.assertIn("credentials", str(cm.exception))

    def test_allows_query_text_in_operation_path(self):
        cfg = load_config(self._write(BASE.replace("/users/{user_id}", "/users?email={email}")))
        self.assertEqual(cfg.operations["get_user"].path, "/users?email={email}")

    def test_rejects_rule_target_without_writable_secret(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(self._write(BASE + """

[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
secret_update_rules = [
  { secret_name = "auth_token", response_type = "json", extract_path = "token", match_status = "200" },
]

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
"""))
        self.assertIn("not declared writable", str(cm.exception))

    def test_rejects_yaml_rule_until_phase_two_adds_it(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(self._write(BASE + """

[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/login"
secret_update_rules = [
  { secret_name = "auth_token", response_type = "yaml", extract_path = "token", match_status = "200" },
]

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
writable = true
"""))
        self.assertIn("response_type", str(cm.exception))

    def test_rejects_literal_braces_in_path(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(self._write(BASE.replace("/users/{user_id}", "/users/{+tail}")))
        self.assertIn("single-segment", str(cm.exception))

    def test_path_portion_rejects_space(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(self._write(BASE.replace("/users/{user_id}", "/My Folder/{user_id}")))
        self.assertIn("path portion", str(cm.exception))

    def test_query_portion_allows_space_and_single_quote(self):
        cfg = load_config(self._write(BASE.replace(
            "/users/{user_id}",
            "/users?email={email}&label=it's+good",
        )))
        self.assertEqual(
            cfg.operations["get_user"].path,
            "/users?email={email}&label=it's+good",
        )

    def test_query_portion_still_rejects_hash_fragment(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(self._write(BASE.replace("/users/{user_id}", "/users?x=1#frag")))
        self.assertIn("fragment", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
