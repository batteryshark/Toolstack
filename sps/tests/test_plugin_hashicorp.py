"""plugins/hashicorp_vault: KV-v2 round trip + auth header."""
import json
import unittest
from unittest import mock

from sps.config import VaultBlock
from sps.plugins.hashicorp_vault import HashicorpVaultPlugin


class _StubResponse:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self, size=-1):
        result, self._b = self._b[:size], self._b[size:]
        return result

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class RoundTrip(unittest.TestCase):
    BLOCK = VaultBlock(
        url="https://vault.example.com",
        token="T-1",
        mount="secret",
    )

    def test_get_secret_kv_v2(self):
        secrets = {"data": {"data": {"API_KEY": "V"}}}
        with mock.patch("sps.transport.urlopen", return_value=_StubResponse(secrets)):
            plugin = HashicorpVaultPlugin(self.BLOCK)
            plugin.connect()
            self.assertEqual(plugin.get_secret("API_KEY", "echo"), "V")

    def test_write_secret_kv_v2_posts_full_data_object(self):
        captured: list[tuple[str, str, bytes]] = []
        def fake_urlopen(req, timeout=None):
            captured.append((req.method, req.full_url, req.data))
            if req.method == "GET":
                return _StubResponse({"data": {"data": {"sibling": "preserve"}, "metadata": {"version": 7}}})
            return _StubResponse({})
        with mock.patch("sps.transport.urlopen", side_effect=fake_urlopen):
            plugin = HashicorpVaultPlugin(self.BLOCK)
            plugin.connect()
            plugin.write_secret("API_KEY", "echo", "V-new")
        method, url, body = captured[1]
        self.assertEqual(method, "POST")
        self.assertIn("/v1/secret/data/echo", url)
        self.assertEqual(json.loads(body.decode()), {"data": {"API_KEY": "V-new", "sibling": "preserve"}, "options": {"cas": 7}})

    def test_requests_carry_x_vault_token(self):
        # urllib.request.Request normalizes header names via email-message style
        # (`X-Vault-Token` -> `X-vault-token`); assert via the case-preserving
        # dict directly. This pins the production plugin's call shape.
        secrets = {"data": {"data": {"API_KEY": "V"}}}
        captured: list[dict] = []
        def fake_urlopen(req, timeout=None):
            captured.append(dict(req.headers))
            return _StubResponse(secrets)
        with mock.patch("sps.transport.urlopen", side_effect=fake_urlopen):
            plugin = HashicorpVaultPlugin(self.BLOCK)
            plugin.connect()
            plugin.get_secret("API_KEY", "echo")
        headers = captured[0]
        # urllib normalizes "X-Vault-Token" -> "X-vault-token"
        self.assertEqual(headers.get("X-vault-token"), "T-1")

    def test_missing_field_raises_keyerror(self):
        secrets = {"data": {"data": {}}}
        with mock.patch("sps.transport.urlopen", return_value=_StubResponse(secrets)):
            plugin = HashicorpVaultPlugin(self.BLOCK)
            plugin.connect()
            with self.assertRaises(KeyError):
                plugin.get_secret("MISSING", "echo")
