"""Secret backend resolution (FileBackend, InfisicalBackend, get_backend)."""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import toolyard.secrets as secrets_mod
from toolyard.config import SecretSpec, ToolDef
from toolyard.secrets import FileBackend, InfisicalBackend, VaultBackend, get_backend

# A self-contained fixture tool that declares a secret (the shipped echo demo no longer does).
_FIXTURE = ToolDef(id="echo", type="api", port=4601, command="python3 app.py", image=None,
                   secrets=(SecretSpec("api_key", "API_KEY"),), path=Path("."))


def _toml_file(text: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    f.write(text)
    f.close()
    return f.name


class Resolve(unittest.TestCase):
    def test_resolves_declared_secret_by_field(self):
        path = _toml_file('[echo]\nAPI_KEY = "dev-secret-123"\n')
        self.addCleanup(os.unlink, path)
        resolved = FileBackend(path).resolve(_FIXTURE)
        self.assertEqual(resolved, {"api_key": "dev-secret-123"})

    def test_missing_secret_raises(self):
        path = _toml_file('[other]\nX = "y"\n')
        self.addCleanup(os.unlink, path)
        with self.assertRaises(KeyError):
            FileBackend(path).resolve(_FIXTURE)

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
        id="demo", type="api", port=1234, command=None, image=None,
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


class _FakeInfisical(BaseHTTPRequestHandler):
    """A wire-faithful, in-memory Infisical v4 over real HTTP — so the backend's actual
    urllib / auth / project-lookup / parse / PATCH code is exercised (the tests above
    monkeypatch `_request`, skipping all of it). One project ("Proj"/"p1"), one path."""

    store: dict = {}        # secretKey -> secretValue
    login_count = 0
    CID, CSECRET = "cid", "csecret"

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def _send(self, status: int, obj: dict) -> None:
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _authed(self) -> bool:
        return self.headers.get("Authorization") == "Bearer fake-token"

    def do_POST(self):
        if self.path == "/api/v1/auth/universal-auth/login":
            b = self._body()
            if b.get("clientId") != self.CID or b.get("clientSecret") != self.CSECRET:
                return self._send(401, {"error": "unauthorized"})
            type(self).login_count += 1
            return self._send(200, {"accessToken": "fake-token", "expiresIn": 600})
        self._send(404, {"error": "nf"})

    def do_GET(self):
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/api/v1/projects":
            return self._send(200, {"projects": [{"id": "p1", "slug": "Proj", "name": "Proj"}]})
        if self.path.startswith("/api/v4/secrets"):
            return self._send(200, {"secrets": [{"secretKey": k, "secretValue": v}
                                                for k, v in type(self).store.items()]})
        self._send(404, {"error": "nf"})

    def do_PATCH(self):
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        prefix = "/api/v4/secrets/"
        if self.path.startswith(prefix):
            field = urllib.parse.unquote(self.path[len(prefix):])
            type(self).store[field] = self._body().get("secretValue")
            return self._send(200, {"secret": {"secretKey": field}})
        self._send(404, {"error": "nf"})

    def log_message(self, *a):
        pass


class InfisicalHTTP(unittest.TestCase):
    """InfisicalBackend driven over REAL HTTP against the fake above — auth, project
    lookup, secret parse, token caching, the write→re-read round trip, and the
    HTTPError path, none of which the `_request`-monkeypatch tests reach."""

    def setUp(self):
        _FakeInfisical.store = {"API_KEY": "v1"}
        _FakeInfisical.login_count = 0
        self.server = HTTPServer(("127.0.0.1", 0), _FakeInfisical)
        self.addCleanup(self.server.server_close)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.creds_dir = tempfile.mkdtemp()
        Path(self.creds_dir, "demo.env").write_text(  # item defaults to the tool id "demo"
            "INFISICAL_CLIENT_ID=cid\nINFISICAL_CLIENT_SECRET=csecret\n")
        self.backend = InfisicalBackend(
            host=f"http://127.0.0.1:{self.server.server_address[1]}",
            credentials_dir=self.creds_dir, environment="dev", default_vault="Proj")

    def _tool(self, field="API_KEY"):
        return _tool(SecretSpec("api_key", field, writable=True))

    def test_resolve_over_real_http(self):
        self.assertEqual(self.backend.resolve(self._tool()), {"api_key": "v1"})

    def test_write_then_reread_round_trip(self):
        # T-005: a tool writes a new value; a later import sees it (no stale value cache).
        self.assertEqual(self.backend.resolve(self._tool()), {"api_key": "v1"})
        self.backend.update(self._tool(), "api_key", "v2")
        self.assertEqual(self.backend.resolve(self._tool()), {"api_key": "v2"})

    def test_access_token_is_cached_across_calls(self):
        self.backend.resolve(self._tool())
        self.backend.resolve(self._tool())
        self.assertEqual(_FakeInfisical.login_count, 1)  # logged in once, token reused

    def test_http_error_becomes_runtime_error(self):
        Path(self.creds_dir, "demo.env").write_text(  # wrong creds -> login 401
            "INFISICAL_CLIENT_ID=wrong\nINFISICAL_CLIENT_SECRET=wrong\n")
        b = InfisicalBackend(host=self.backend.host, credentials_dir=self.creds_dir,
                             environment="dev", default_vault="Proj")
        with self.assertRaises(RuntimeError):
            b.resolve(self._tool())

    def test_unknown_field_raises_over_http(self):
        with self.assertRaises(KeyError):
            self.backend.resolve(self._tool(field="MISSING"))


@unittest.skipUnless(
    os.environ.get("TOOLSTACK_INFISICAL_HOST") and os.environ.get("TOOLSTACK_INFISICAL_TEST_VAULT"),
    "set TOOLSTACK_INFISICAL_HOST + _TEST_VAULT/_TEST_ITEM/_TEST_FIELD (+ creds dir) for the live test",
)
class InfisicalLive(unittest.TestCase):
    """Opt-in: verify the pinned v4 contract against a REAL Infisical. Reads
    TOOLSTACK_INFISICAL_* (host/env/creds dir, via from_env) plus _TEST_VAULT/_TEST_ITEM/
    _TEST_FIELD naming a secret the configured machine identity can read."""

    def test_resolves_a_real_secret(self):
        backend = InfisicalBackend.from_env()
        spec = SecretSpec("probe", os.environ["TOOLSTACK_INFISICAL_TEST_FIELD"],
                          vault=os.environ["TOOLSTACK_INFISICAL_TEST_VAULT"],
                          item=os.environ.get("TOOLSTACK_INFISICAL_TEST_ITEM"))
        resolved = backend.resolve(_tool(spec))
        self.assertIsInstance(resolved["probe"], str)
        self.assertTrue(resolved["probe"])  # non-empty


def _has_cryptography() -> bool:
    try:
        import cryptography.fernet  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


@unittest.skipUnless(_has_cryptography(), "vault backend needs the 'cryptography' extra")
class Vault(unittest.TestCase):
    """Local encrypted vault: round-trip, encrypted-at-rest, fail-closed on wrong
    passphrase / tamper, the two write paths (operator set_secret vs runtime update),
    and selection via get_backend (T-025)."""

    PW = "correct horse battery staple"

    def _path(self) -> str:
        d = tempfile.mkdtemp(prefix="tsr-vault-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return os.path.join(d, "vault.json")

    def test_init_set_resolve_round_trip(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")
        resolved = VaultBackend(path, self.PW).resolve(_tool(SecretSpec("api_key", "API_KEY")))
        self.assertEqual(resolved, {"api_key": "v1"})

    def test_has_secret_reports_membership_without_value(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")
        vault = VaultBackend(path, self.PW)
        self.assertTrue(vault.has_secret("demo", "API_KEY"))   # set
        self.assertFalse(vault.has_secret("demo", "OTHER"))    # declared elsewhere, not set
        self.assertFalse(vault.has_secret("nope", "API_KEY"))  # unknown tool

    def test_encrypted_at_rest(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "super-secret-value")
        blob = Path(path).read_text(encoding="utf-8")
        self.assertNotIn("super-secret-value", blob)  # value is ciphertext, not plaintext
        self.assertNotIn("API_KEY", blob)             # even the field name is inside the cipher

    def test_wrong_passphrase_fails_closed(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")
        with self.assertRaises(RuntimeError):
            VaultBackend(path, "wrong passphrase")

    def test_tamper_is_detected(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")
        env = json.loads(Path(path).read_text(encoding="utf-8"))
        ct = env["ciphertext"]
        env["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]  # flip a byte -> bad MAC
        Path(path).write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(RuntimeError):
            VaultBackend(path, self.PW)

    def test_update_writeback_round_trip(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "TOKEN", "old")
        VaultBackend(path, self.PW).update(
            _tool(SecretSpec("token", "TOKEN", writable=True)), "token", "new")
        resolved = VaultBackend(path, self.PW).resolve(_tool(SecretSpec("token", "TOKEN")))
        self.assertEqual(resolved, {"token": "new"})

    def test_update_rejects_non_writable(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        with self.assertRaises(PermissionError):
            VaultBackend(path, self.PW).update(_tool(SecretSpec("token", "TOKEN")), "token", "x")

    def test_resolve_missing_field_raises(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        with self.assertRaises(KeyError):
            VaultBackend(path, self.PW).resolve(_tool(SecretSpec("api_key", "API_KEY")))

    def test_missing_vault_gives_clear_error(self):
        with self.assertRaises(FileNotFoundError) as cm:
            VaultBackend(self._path(), self.PW)  # never init'd
        self.assertIn("vault-init", str(cm.exception))

    def test_init_refuses_to_clobber(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        with self.assertRaises(FileExistsError):
            VaultBackend.init(path, self.PW)

    def test_init_rejects_empty_passphrase(self):
        with self.assertRaises(ValueError):
            VaultBackend.init(self._path(), "")

    def test_file_is_0600(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")  # rewrite keeps it
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))

    def test_unsupported_version_fails_closed(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        env = json.loads(Path(path).read_text(encoding="utf-8"))
        env["version"] = 999
        Path(path).write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(RuntimeError):
            VaultBackend(path, self.PW)

    def test_params_read_from_envelope_survive_default_change(self):
        # A vault written with one scrypt cost must still open if the compiled-in default
        # changes — the params travel in the envelope, not the code.
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")
        with mock.patch.object(secrets_mod, "_SCRYPT_N", secrets_mod._SCRYPT_N * 2):
            resolved = VaultBackend(path, self.PW).resolve(_tool(SecretSpec("api_key", "API_KEY")))
        self.assertEqual(resolved, {"api_key": "v1"})

    def test_get_backend_vault_from_env(self):
        path = self._path()
        VaultBackend.init(path, self.PW)
        VaultBackend(path, self.PW).set_secret("demo", "API_KEY", "v1")
        with mock.patch.dict(os.environ, {"TOOLSTACK_VAULT_FILE": path,
                                          "TOOLSTACK_VAULT_PASSPHRASE": self.PW}):
            backend = get_backend("vault")
            self.assertIsInstance(backend, VaultBackend)
            self.assertEqual(backend.resolve(_tool(SecretSpec("api_key", "API_KEY"))),
                             {"api_key": "v1"})


class Factory(unittest.TestCase):
    def test_file_backend_by_name(self):
        path = _toml_file('[echo]\nAPI_KEY = "v"\n')
        self.addCleanup(os.unlink, path)
        self.assertIsInstance(get_backend("file", secrets_file=path), FileBackend)

    def test_unknown_backend_raises(self):
        with self.assertRaises(ValueError):
            get_backend("nope")



class InfisicalRetry(unittest.TestCase):
    """_request retries transient (429/5xx/network) failures, fails auth fast, then gives up."""

    def _backend(self):
        import tempfile
        return InfisicalBackend(host="https://infisical.test",
                                credentials_dir=tempfile.mkdtemp(),
                                environment="dev", default_vault="Proj")

    @staticmethod
    def _http_error(code):
        import io
        import urllib.error
        return urllib.error.HTTPError("https://infisical.test/x", code, "err", {}, io.BytesIO(b""))

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok": true}'

    def test_retries_5xx_then_succeeds(self):
        calls = []

        def fake_urlopen(req, timeout=None):
            calls.append(1)
            if len(calls) < 3:
                raise self._http_error(503)
            return self._Resp()

        with mock.patch("toolyard.secrets.urllib.request.urlopen", fake_urlopen), \
                mock.patch("toolyard.secrets.time.sleep"):
            out = self._backend()._request("GET", "https://infisical.test/x", {}, None)
        self.assertEqual(out, {"ok": True})
        self.assertEqual(len(calls), 3)  # two transient failures, then success

    def test_auth_error_is_not_retried(self):
        calls = []

        def fake_urlopen(req, timeout=None):
            calls.append(1)
            raise self._http_error(401)

        with mock.patch("toolyard.secrets.urllib.request.urlopen", fake_urlopen), \
                mock.patch("toolyard.secrets.time.sleep"):
            with self.assertRaises(RuntimeError) as cm:
                self._backend()._request("GET", "https://infisical.test/x", {}, None)
        self.assertEqual(len(calls), 1)            # 401 is terminal — no retry
        self.assertIn("auth", str(cm.exception).lower())

    def test_exhausts_retries_on_persistent_5xx(self):
        calls = []

        def fake_urlopen(req, timeout=None):
            calls.append(1)
            raise self._http_error(503)

        b = self._backend()
        with mock.patch("toolyard.secrets.urllib.request.urlopen", fake_urlopen), \
                mock.patch("toolyard.secrets.time.sleep"):
            with self.assertRaises(RuntimeError) as cm:
                b._request("GET", "https://infisical.test/x", {}, None)
        self.assertEqual(len(calls), b._RETRIES)   # all attempts used
        self.assertIn("transient", str(cm.exception).lower())

if __name__ == "__main__":
    unittest.main()
