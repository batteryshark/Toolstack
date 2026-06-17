"""Secret backend resolution (FileBackend, InfisicalBackend, get_backend)."""

import os
import tempfile
import unittest
from pathlib import Path

from toolyard.config import SecretSpec, ToolDef, load
from toolyard.secrets import FileBackend, InfisicalBackend, get_backend

REPO = Path(__file__).resolve().parents[2]
TOOL_TOML = REPO / "tools" / "echo_rest" / "toolyard.toml"


def _toml_file(text: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    f.write(text)
    f.close()
    return f.name


class Resolve(unittest.TestCase):
    def test_resolves_declared_secret_by_field(self):
        path = _toml_file('[echo]\nAPI_KEY = "dev-secret-123"\n')
        self.addCleanup(os.unlink, path)
        resolved = FileBackend(path).resolve(load(TOOL_TOML))
        self.assertEqual(resolved, {"api_key": "dev-secret-123"})

    def test_missing_secret_raises(self):
        path = _toml_file('[other]\nX = "y"\n')
        self.addCleanup(os.unlink, path)
        with self.assertRaises(KeyError):
            FileBackend(path).resolve(load(TOOL_TOML))

    def test_update_writes_writable_secret_back(self):
        path = _toml_file('[demo]\nTOKEN = "old"\n')
        self.addCleanup(os.unlink, path)
        backend = FileBackend(path)
        backend.update(_tool(SecretSpec("token", "TOKEN", writable=True)), "token", "new")
        # A fresh read sees the persisted value.
        spec = SecretSpec("token", "TOKEN", writable=True)
        self.assertEqual(FileBackend(path).resolve(_tool(spec)), {"token": "new"})

    def test_update_rejects_non_writable(self):
        path = _toml_file('[demo]\nTOKEN = "old"\n')
        self.addCleanup(os.unlink, path)
        with self.assertRaises(PermissionError):
            FileBackend(path).update(_tool(SecretSpec("token", "TOKEN")), "token", "x")


def _tool(*secrets: SecretSpec) -> ToolDef:
    return ToolDef(
        id="demo", type="rest", port=1234, command=None, image=None,
        secrets=tuple(secrets), path=Path("."),
    )


class Infisical(unittest.TestCase):
    """Drive InfisicalBackend with a stubbed HTTP layer (no network)."""

    def _backend(self, secrets_at_path):
        creds_dir = tempfile.mkdtemp()
        Path(creds_dir, "demo-item.env").write_text(
            "INFISICAL_CLIENT_ID=cid\nINFISICAL_CLIENT_SECRET=csecret\n"
        )
        b = InfisicalBackend(host="https://infisical.test", credentials_dir=creds_dir,
                             environment="dev", default_vault="Proj")

        def fake_request(method, url, headers, body):
            if url.endswith("/api/v1/auth/universal-auth/login"):
                return {"accessToken": "tok", "expiresIn": 600}
            if "/api/v1/projects" in url:
                return {"projects": [{"id": "p1", "slug": "Proj"}]}
            if "/api/v4/secrets" in url:
                return {"secrets": secrets_at_path}
            raise AssertionError(f"unexpected request {method} {url}")

        b._request = fake_request
        return b

    def test_resolves_by_vault_item_field(self):
        b = self._backend([{"secretKey": "username", "secretValue": "alice"}])
        resolved = b.resolve(_tool(
            SecretSpec("app_username", "username", vault="Proj", item="demo-item")))
        self.assertEqual(resolved, {"app_username": "alice"})

    def test_item_defaults_to_tool_id(self):
        # No item on the spec -> credentials/path derive from the tool id ("demo").
        creds_dir = tempfile.mkdtemp()
        Path(creds_dir, "demo.env").write_text(
            "INFISICAL_CLIENT_ID=cid\nINFISICAL_CLIENT_SECRET=csecret\n")
        b = InfisicalBackend(host="https://infisical.test", credentials_dir=creds_dir,
                             environment="dev", default_vault="Proj")
        b._request = lambda m, u, h, body: (
            {"accessToken": "t", "expiresIn": 600} if "login" in u
            else {"projects": [{"id": "p1", "slug": "Proj"}]} if "projects" in u
            else {"secrets": [{"secretKey": "K", "secretValue": "v"}]})
        self.assertEqual(b.resolve(_tool(SecretSpec("k", "K"))), {"k": "v"})

    def test_missing_field_raises(self):
        b = self._backend([{"secretKey": "other", "secretValue": "x"}])
        with self.assertRaises(KeyError):
            b.resolve(_tool(SecretSpec("k", "missing", vault="Proj", item="demo-item")))

    def test_no_vault_raises(self):
        creds_dir = tempfile.mkdtemp()
        b = InfisicalBackend(host="https://infisical.test", credentials_dir=creds_dir,
                             environment="dev")  # no default_vault
        with self.assertRaises(ValueError):
            b.resolve(_tool(SecretSpec("k", "K", item="demo-item")))

    def test_update_patches_writable_field(self):
        b = self._backend([])
        seen = {}

        def fake_request(method, url, headers, body):
            if "login" in url:
                return {"accessToken": "t", "expiresIn": 600}
            if "/api/v1/projects" in url:
                return {"projects": [{"id": "p1", "slug": "Proj"}]}
            seen.update(method=method, url=url, body=body)
            return {}

        b._request = fake_request
        b.update(_tool(SecretSpec("tok", "TOKEN", writable=True, vault="Proj", item="demo-item")),
                 "tok", "new-value")
        self.assertEqual(seen["method"], "PATCH")
        self.assertTrue(seen["url"].endswith("/api/v4/secrets/TOKEN"))
        self.assertEqual(seen["body"]["secretValue"], "new-value")
        self.assertEqual(seen["body"]["secretPath"], "/demo-item")

    def test_update_rejects_non_writable(self):
        b = self._backend([])
        with self.assertRaises(PermissionError):
            b.update(_tool(SecretSpec("tok", "TOKEN", vault="Proj", item="demo-item")),
                     "tok", "x")


class Factory(unittest.TestCase):
    def test_file_backend_by_name(self):
        path = _toml_file('[echo]\nAPI_KEY = "v"\n')
        self.addCleanup(os.unlink, path)
        self.assertIsInstance(get_backend("file", secrets_file=path), FileBackend)

    def test_unknown_backend_raises(self):
        with self.assertRaises(ValueError):
            get_backend("nope")


if __name__ == "__main__":
    unittest.main()
