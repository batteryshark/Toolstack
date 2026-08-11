import base64
import shutil
import tempfile
import unittest
from pathlib import Path

from toolstack_forwarder.config import load_config
from toolstack_forwarder.request_builder import RequestBuildError, build_request


class _FakeSecrets:
    """In-memory stand-in for sps.tool_sdk.SecretClient. Tests construct this
    with the subset of secrets the operation expects; missing keys raise
    KeyError (mirroring SecretClient.get)."""

    def __init__(self, table):
        self._t = dict(table)
    def get(self, name):
        if name not in self._t:
            raise KeyError(name)
        return self._t[name]





TOML = """\
id = "jira"
type = "rest"
base_url = "https://api.example.test/v1"

[entrypoint]
port = 4600
command = "python3 -m toolstack_forwarder"

[[operations]]
name = "get_user"
risk = "read"
verb = "GET"
path = "/users/{user_id}"
allowed_headers = ["X-Trace"]

[[operations]]
name = "login"
risk = "write"
verb = "POST"
path = "/tenants/{tenant}/login"
allowed_headers = ["Authorization"]
body_kind = "text"
body_content_type = "application/json"

[[operations]]
name = "upload"
risk = "write"
verb = "POST"
path = "/files/{file_id}"
body_kind = "binary"

[[operations]]
name = "search"
risk = "read"
verb = "GET"
path = "/search?q={query}&tenant={tenant}"

[[secrets]]
name = "auth_token"
field = "AUTH_TOKEN"
"""


class RequestBuilder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = Path(self.tmp)
        self.toml = self.root / "toolyard.toml"
        self.toml.write_text(TOML)
        self.secrets = _FakeSecrets({"auth_token": "sekret"})
        self.cfg = load_config(self.toml)

    def build(self, op, args, max_body=1024):
        return build_request(self.cfg, op, args, self.secrets, max_body=max_body)

    def test_hydrates_path_and_joins_base_path(self):
        req = self.build("get_user", {"variables": {"user_id": "u+42"}, "headers": {"X-Trace": "abc"}})
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url, "https://api.example.test/v1/users/u%2B42")
        self.assertEqual(req.headers["X-Trace"], "abc")
        self.assertIsNone(req.body)

    def test_hydrates_query_variables_and_preserves_query_string(self):
        req = self.build("search", {"variables": {"query": "a/b+c", "tenant": "acme"}})
        self.assertEqual(req.url, "https://api.example.test/v1/search?q=a%2Fb%2Bc&tenant=acme")

    def test_rejects_variable_slash_dot_whitespace_non_ascii_and_encoded_dot(self):
        bad = ["a/b", "u 42", "caf\xe9"]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(RequestBuildError) as cm:
                    self.build("get_user", {"variables": {"user_id": value}})
                self.assertEqual(cm.exception.code, "invalid_variable")
        # Disabled: single-dot values like "a.b" and "%2E" are intentionally
        # accepted as path variables — only ".." sequences are rejected.

    def test_path_variable_still_rejects_internal_space(self):
        with self.assertRaises(RequestBuildError) as cm:
            self.build("get_user", {"variables": {"user_id": "u 42"}})
        self.assertEqual(cm.exception.code, "invalid_variable")

    def test_allows_space_and_single_quote_in_query_value(self):
        req = self.build("search", {"variables": {"query": "hello world 'foo'", "tenant": "acme"}})
        self.assertEqual(req.url, "https://api.example.test/v1/search?q=hello%20world%20%27foo%27&tenant=acme")

    def test_strips_surrounding_query_variable_whitespace(self):
        req = self.build("search", {"variables": {"query": "  hello world  ", "tenant": "acme"}})
        self.assertEqual(req.url, "https://api.example.test/v1/search?q=hello%20world&tenant=acme")

    def test_drops_absent_query_variable_pair(self):
        req = self.build("search", {"variables": {"query": "foo"}})
        self.assertEqual(req.url, "https://api.example.test/v1/search?q=foo")

    def test_drops_absent_query_variable_when_other_pair_remains(self):
        req = self.build("search", {"variables": {"tenant": "acme"}})
        self.assertEqual(req.url, "https://api.example.test/v1/search?tenant=acme")

    def test_drops_all_query_variables_and_removes_question_mark(self):
        req = self.build("search", {"variables": {}})
        self.assertEqual(req.url, "https://api.example.test/v1/search")

    def test_drops_absent_query_variable_in_middle(self):
        path = "/items?a={a}&b={b}&c={c}"
        op = type("Op", (), {"path": path, "verb": "GET", "allowed_headers": frozenset(),
                              "body_kind": "none", "body_content_type": None,
                              "body_substitution": False})()
        from toolstack_forwarder.request_builder import _hydrate_path
        rendered = _hydrate_path(op, {"variables": {"a": "foo", "c": "bar"}})
        self.assertEqual(rendered, "/items?a=foo&c=bar")

    def test_keeps_static_query_text_even_when_no_variables(self):
        path = "/items?debug=true&q={q}"
        op = type("Op", (), {"path": path, "verb": "GET", "allowed_headers": frozenset(),
                              "body_kind": "none", "body_content_type": None,
                              "body_substitution": False})()
        from toolstack_forwarder.request_builder import _hydrate_path
        rendered = _hydrate_path(op, {"variables": {}})
        self.assertEqual(rendered, "/items?debug=true")

    def test_strips_surrounding_path_variable_whitespace(self):
        req = self.build("get_user", {"variables": {"user_id": " u42\n"}})
        self.assertEqual(req.url, "https://api.example.test/v1/users/u42")

    def test_rejects_missing_variable(self):
        with self.assertRaises(RequestBuildError) as cm:
            self.build("get_user", {"variables": {}})
        self.assertEqual(cm.exception.code, "missing_variable")
        self.assertEqual(cm.exception.fields["name"], "user_id")

    def test_rejects_header_outside_allowlist(self):
        with self.assertRaises(RequestBuildError) as cm:
            self.build("get_user", {"variables": {"user_id": "u42"}, "headers": {"Cookie": "x"}})
        self.assertEqual(cm.exception.code, "header_not_allowed")

    def test_substitutes_secrets_in_headers_and_text_body(self):
        req = self.build(
            "login",
            {
                "variables": {"tenant": "acme"},
                "headers": {"Authorization": "Bearer {{secret:auth_token}}"},
                "body": '{"token":"{{secret:auth_token}}"}',
            },
        )
        self.assertEqual(req.headers["Authorization"], "Bearer sekret")
        self.assertEqual(req.headers["Content-Type"], "application/json")
        self.assertEqual(req.body, b'{"token":"sekret"}')

    def test_rejects_header_control_character_after_substitution(self):
        # Inject a control character via the in-memory fake.
        self.secrets._t["auth_token"] = "bad\r\nHeader: injected"
        with self.assertRaises(RequestBuildError) as cm:
            self.build(
                "login",
                {
                    "variables": {"tenant": "acme"},
                    "headers": {"Authorization": "Bearer {{secret:auth_token}}"},
                    "body": "{}",
                },
            )
        self.assertEqual(cm.exception.code, "invalid_header")

    def test_binary_body_is_base64_decoded_and_substitution_is_off(self):
        req = self.build("upload", {"variables": {"file_id": "f1"}, "body": base64.b64encode(b"\x00abc").decode()})
        self.assertEqual(req.headers["Content-Type"], "application/octet-stream")
        self.assertEqual(req.body, b"\x00abc")

    def test_binary_body_must_be_valid_base64(self):
        with self.assertRaises(RequestBuildError) as cm:
            self.build("upload", {"variables": {"file_id": "f1"}, "body": "not base64"})
        self.assertEqual(cm.exception.code, "invalid_body")

    def test_body_cap_applies_to_outbound_bytes(self):
        with self.assertRaises(RequestBuildError) as cm:
            self.build("login", {"variables": {"tenant": "acme"}, "body": "x" * 5}, max_body=4)
        self.assertEqual(cm.exception.code, "body_too_large")

    def test_none_body_rejects_present_body(self):
        with self.assertRaises(RequestBuildError) as cm:
            self.build("get_user", {"variables": {"user_id": "u42"}, "body": ""})
        self.assertEqual(cm.exception.code, "body_not_allowed")


if __name__ == "__main__":
    unittest.main()
