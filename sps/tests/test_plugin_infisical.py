"""plugins/infisical: round-trip against mocked HTTP."""
import json
import unittest
import urllib.parse
import urllib.error
import io
from unittest import mock

from sps.config import InfisicalBlock
from sps.plugins.infisical import InfisicalPlugin


class _StubResponse:
    def __init__(self, payload, code=200):
        self._stream = io.BytesIO(json.dumps(payload).encode())
        self.code = code

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class RoundTrip(unittest.TestCase):
    BLOCK = InfisicalBlock(
        host="https://inf.example.com",
        vault="ToolServer",
        environment="prod",
        client_id="cid",
        client_secret="csec",
    )

    def test_get_secret(self):
        seq = iter([
            {"accessToken": "T-1", "expiresIn": 600},
            {"projects": [{"id": "P1", "name": "ToolServer"}]},
            # Official getSecretByNameV4 response projection, not a folder.
            # https://infisical.com/docs/api-reference/endpoints/secrets/read.md
            # OpenAPI 3.0.3, info.version 0.0.1; read 2026-10-24.
            {"secret": {"secretKey": "API_KEY", "secretValue": "V"}},
        ])

        def fake_urlopen(req, timeout=None):
            if req.method == "GET" and "/api/v4/" in req.full_url:
                url = urllib.parse.urlsplit(req.full_url)
                self.assertEqual(url.path, "/api/v4/secrets/API_KEY")
                self.assertEqual(urllib.parse.parse_qs(url.query), {
                    "projectId": ["P1"], "environment": ["prod"],
                    "secretPath": ["/echo"], "viewSecretValue": ["true"],
                    "expandSecretReferences": ["true"], "includeImports": ["true"],
                    "type": ["shared"],
                })
            try:
                return _StubResponse(next(seq))
            except StopIteration:
                self.fail("urlopen called too many times")

        plugin = InfisicalPlugin(self.BLOCK)
        with mock.patch("sps.transport.urlopen", side_effect=fake_urlopen):
            plugin.connect()
            value = plugin.get_secret("API_KEY", "echo")
        self.assertEqual(value, "V")

    def test_write_secret_patches(self):
        bodies: list[dict] = []
        seq = iter([
            {"accessToken": "T-1", "expiresIn": 600},                # login
            {"projects": [{"id": "P1", "name": "ToolServer"}]},     # projects
            {"secret": {"secretKey": "API_KEY", "secretValue": "rotated"}},  # PATCH echo
        ])

        def fake_urlopen(req, timeout=None):
            if req.data is not None:
                bodies.append(json.loads(req.data.decode()))
            try:
                return _StubResponse(next(seq))
            except StopIteration:
                self.fail(f"unexpected extra urlopen call: {req.method} {req.full_url}")

        plugin = InfisicalPlugin(self.BLOCK)
        with mock.patch("sps.transport.urlopen", side_effect=fake_urlopen):
            plugin.connect()
            plugin.write_secret("API_KEY", "echo", "rotated")
        patch_body = bodies[-1]
        self.assertEqual(patch_body["secretValue"], "rotated")
        self.assertEqual(patch_body["projectId"], "P1")
        self.assertEqual(patch_body["environment"], "prod")

    def test_missing_secret_raises(self):
        seq = iter([
            {"accessToken": "T-1", "expiresIn": 600},
            {"projects": [{"id": "P1", "name": "ToolServer"}]},
            {"secrets": [], "imports": []},
        ])

        def fake_urlopen(req, timeout=None):
            return _StubResponse(next(seq))

        plugin = InfisicalPlugin(self.BLOCK)
        with mock.patch("sps.transport.urlopen", side_effect=fake_urlopen):
            plugin.connect()
            with self.assertRaises(KeyError):
                plugin.get_secret("MISSING", "echo")

    def test_narrow_response_validation_and_no_list_fallback(self):
        plugin = InfisicalPlugin(self.BLOCK)
        plugin._project_id = "P1"
        for response in ({"secrets": [{"secretKey": "KEY", "secretValue": "sibling"}]},
                         {"secret": {"secretKey": "OTHER", "secretValue": "fake"}},
                         {"secret": {"secretKey": "KEY", "secretValue": 42}},
                         {"secret": {"secretKey": "KEY", "secretValue": "", "secretValueHidden": True}}):
            with mock.patch.object(plugin, "_http", return_value=response) as call:
                with self.assertRaises((KeyError, ValueError)):
                    plugin.get_secret("KEY", "folder")
                self.assertEqual(call.call_count, 1)
                self.assertEqual(call.call_args.args[:2], ("GET", "/api/v4/secrets/KEY"))

    def test_encoded_name_and_unsupported_endpoint_never_falls_back(self):
        plugin = InfisicalPlugin(self.BLOCK)
        plugin._project_id = "P1"
        plugin._token = ("fake", float("inf"))
        error = urllib.error.HTTPError("https://inf.example.com", 404, "unsupported", {}, io.BytesIO())
        with mock.patch("sps.transport.urlopen", side_effect=error) as call:
            with self.assertRaises(RuntimeError):
                plugin.get_secret("key/?#", "nested/folder")
            self.assertEqual(call.call_count, 1)
            self.assertIn("/api/v4/secrets/key%2F%3F%23?", call.call_args.args[0].full_url)
