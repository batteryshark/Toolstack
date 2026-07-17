"""plugins/infisical: round-trip against mocked HTTP."""
import json
import unittest
from unittest import mock

from sps.config import InfisicalBlock
from sps.plugins.infisical import InfisicalPlugin


class _StubResponse:
    def __init__(self, payload, code=200):
        self._payload = payload
        self.code = code

    def read(self):
        return json.dumps(self._payload).encode()

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
            {"secrets": [{"secretKey": "API_KEY", "secretValue": "V"}], "imports": []},
        ])

        def fake_urlopen(req, timeout=None):
            try:
                return _StubResponse(next(seq))
            except StopIteration:
                self.fail("urlopen called too many times")

        plugin = InfisicalPlugin(self.BLOCK)
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
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
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
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
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            plugin.connect()
            with self.assertRaises(KeyError):
                plugin.get_secret("MISSING", "echo")
