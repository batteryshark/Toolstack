"""Secret resolution backends.

Phase 2 ships a dev `FileBackend` that reads values from a local TOML file.
`VaultBackend` is the laptop path: the same shape, but encrypted at rest (no external
server, no plaintext on disk). `InfisicalBackend` is the production backend (Infisical
via its HTTP API, stdlib only). SOPS can follow behind the same `resolve()` interface.
Resolved values flow only to the tool (via the runner); they never reach the broker.

Pick a backend with `get_backend(name)` (or `$TOOLSTACK_SECRET_BACKEND`). Everything here
is stdlib-only EXCEPT `VaultBackend`, which needs the optional `cryptography` extra
(`pip install 'toolstack[vault]'`) and imports it lazily, so the toolyard stays
zero-dependency until you actually use the vault.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import SecretSpec, ToolDef


def writable_spec(tool_def: ToolDef, name: str) -> SecretSpec:
    """Look up a tool's secret by file name, requiring it be declared ``writable``.

    The toolyard enforces this allowlist before a backend write (message-contracts
    §4): only a field a tool declared writable may be patched.
    """
    for spec in tool_def.secrets:
        if spec.name == name:
            if not spec.writable:
                raise PermissionError(f"{tool_def.id}.{name} is not writable")
            return spec
    raise KeyError(f"{tool_def.id} has no secret named {name!r}")


class FileBackend:
    """Dev backend: a TOML file shaped as ``[<tool_id>]  FIELD = "value"``.

    For real deployments this is a SOPS-encrypted file or Infisical; the contract
    is just ``resolve(tool_def) -> {secret_name: value}`` (plus ``update`` for
    writable fields).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        with open(path, "rb") as f:
            self._data = tomllib.load(f)

    def resolve(self, tool_def: ToolDef) -> dict[str, str]:
        tool_secrets = self._data.get(tool_def.id, {})
        resolved: dict[str, str] = {}
        for spec in tool_def.secrets:
            if spec.field not in tool_secrets:
                raise KeyError(
                    f"secret backend is missing {tool_def.id}.{spec.field}"
                )
            resolved[spec.name] = str(tool_secrets[spec.field])
        return resolved

    def update(self, tool_def: ToolDef, name: str, value: str) -> None:
        """Persist a writable secret back to the TOML file (dev backend)."""
        spec = writable_spec(tool_def, name)
        self._data.setdefault(tool_def.id, {})[spec.field] = value
        self._path.write_text(_dump_toml(self._data), encoding="utf-8")


def _dump_toml(data: dict) -> str:
    """Serialize the 2-level ``{tool_id: {FIELD: str}}`` dev-secrets shape (stdlib
    has a TOML reader but no writer; this file is exactly this shape)."""
    lines = []
    for section, fields in data.items():
        lines.append(f"[{section}]")
        for key, value in fields.items():
            escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
        lines.append("")
    return "\n".join(lines)


# --- Local encrypted vault (the laptop path: no server, no plaintext on disk) ------
#
# Same shape as FileBackend ({tool_id: {FIELD: value}}), but the file is an encrypted
# envelope: a passphrase is stretched with scrypt (stdlib) into a Fernet key (the
# `cryptography` extra), which AEAD-encrypts the JSON. Like every backend, the toolyard
# reads it and the broker never does. `cryptography` is imported lazily, so the toolyard
# is stdlib-only until the vault is actually used.

_VAULT_VERSION = 1
_SCRYPT_N = 2 ** 14            # ~16 MB, tens of ms: interactive-grade stretching
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024  # headroom for the params above (else scrypt errors)


def _default_vault_file() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return str(Path(base) / "toolstack" / "vault.json")


def _vault_passphrase() -> str:
    """The vault passphrase, from `TOOLSTACK_VAULT_PASSPHRASE` or `_PASSPHRASE_FILE`.
    Fails closed if neither is set (the toolyard/admin resolve non-interactively).

    The env value is used verbatim (exact by construction); a passphrase *file* commonly
    carries a trailing newline, so it is stripped. Provision the SAME passphrase the same
    way on both sides, or a stray newline reads as "wrong passphrase"."""
    direct = os.environ.get("TOOLSTACK_VAULT_PASSPHRASE")
    if direct:
        return direct
    path = os.environ.get("TOOLSTACK_VAULT_PASSPHRASE_FILE")
    if path:
        value = Path(path).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(f"{path}: vault passphrase file is empty")
        return value
    raise ValueError(
        "vault backend needs TOOLSTACK_VAULT_PASSPHRASE or TOOLSTACK_VAULT_PASSPHRASE_FILE"
    )


def _fernet():
    """Lazy import: keeps the toolyard stdlib-only until the vault is actually used."""
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "the vault backend needs the 'cryptography' package. Install the extra: "
            "pip install 'toolstack[vault]'"
        ) from exc
    return Fernet, InvalidToken


def _vault_key(passphrase: str, salt: bytes, n: int = _SCRYPT_N,
               r: int = _SCRYPT_R, p: int = _SCRYPT_P) -> bytes:
    """Stretch the passphrase (scrypt, stdlib) into a urlsafe-base64 Fernet key, using the
    KDF params the vault was written with. `maxmem` bounds the memory, so tampered params
    that demand more fail closed with a clear error rather than a raw scrypt traceback."""
    try:
        dk = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=32, maxmem=_SCRYPT_MAXMEM)
    except (ValueError, OverflowError) as exc:
        raise RuntimeError(f"vault: unsupported KDF parameters (n={n}, r={r}, p={p})") from exc
    return base64.urlsafe_b64encode(dk)


def _write_vault(path: Path, salt: bytes, key: bytes, data: dict,
                 params: tuple[int, int, int] = (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)) -> None:
    Fernet, _ = _fernet()
    n, r, p = params
    token = Fernet(key).encrypt(json.dumps(data).encode("utf-8"))
    envelope = {
        "version": _VAULT_VERSION, "kdf": "scrypt",
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "n": n, "r": r, "p": p,
        "ciphertext": token.decode("ascii"),
    }
    blob = json.dumps(envelope, indent=2).encode("utf-8")
    # Write 0o600 from creation (no world-readable window) and rename into place (atomic:
    # a concurrent reader sees the old vault or the new one, never a torn half-write).
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class VaultBackend:
    """Local, encrypted-at-rest secret backend: the laptop path (no Infisical, no
    plaintext `secrets.toml`). Drop-in with the other backends (`resolve` + `update`).

    The file is a JSON envelope (version, scrypt salt+params, Fernet ciphertext); the
    passphrase never lands next to the ciphertext. Create an empty vault with
    `toolyard vault-init`, provision fields with `toolyard vault-set`.
    """

    def __init__(self, path, passphrase: str) -> None:
        self._path = Path(path)
        if not self._path.exists():
            raise FileNotFoundError(
                f"no vault at {self._path}: create one with `toolyard vault-init`"
            )
        envelope = json.loads(self._path.read_text(encoding="utf-8"))
        if envelope.get("version") != _VAULT_VERSION:
            raise RuntimeError(
                f"vault {self._path}: unsupported version {envelope.get('version')!r} "
                f"(this build writes v{_VAULT_VERSION})"
            )
        self._salt = base64.urlsafe_b64decode(envelope["salt"])
        # Derive with the params the vault was WRITTEN with (read back from the envelope),
        # so changing the compiled-in defaults never bricks an existing vault.
        self._params = (int(envelope["n"]), int(envelope["r"]), int(envelope["p"]))
        self._key = _vault_key(passphrase, self._salt, *self._params)
        self._data = self._decrypt(envelope["ciphertext"])

    def _decrypt(self, token: str) -> dict:
        Fernet, InvalidToken = _fernet()
        try:
            plaintext = Fernet(self._key).decrypt(token.encode("ascii"))
        except InvalidToken as exc:
            raise RuntimeError(
                f"vault {self._path}: wrong passphrase or the file is corrupted/tampered"
            ) from exc
        return json.loads(plaintext)

    def _persist(self) -> None:
        _write_vault(self._path, self._salt, self._key, self._data, self._params)

    def resolve(self, tool_def: ToolDef) -> dict[str, str]:
        tool_secrets = self._data.get(tool_def.id, {})
        resolved: dict[str, str] = {}
        for spec in tool_def.secrets:
            if spec.field not in tool_secrets:
                raise KeyError(f"secret backend is missing {tool_def.id}.{spec.field}")
            resolved[spec.name] = str(tool_secrets[spec.field])
        return resolved

    def update(self, tool_def: ToolDef, name: str, value: str) -> None:
        """Runtime writeback path (message-contracts §4): only a field the tool declared
        `writable` may be patched."""
        spec = writable_spec(tool_def, name)
        self._data.setdefault(tool_def.id, {})[spec.field] = value
        self._persist()

    def set_secret(self, tool_id: str, field: str, value: str) -> None:
        """Operator provisioning path (CLI/admin): set any field. Not gated on `writable`:
        that allowlist governs the tool writing back at runtime, not the operator
        filling the vault."""
        self._data.setdefault(tool_id, {})[field] = value
        self._persist()

    def has_secret(self, tool_id: str, field: str) -> bool:
        """Whether a value is provisioned for ``tool_id.field``, for the admin to show set/unset
        status WITHOUT exposing the value."""
        return field in self._data.get(tool_id, {})

    @classmethod
    def init(cls, path, passphrase: str) -> "VaultBackend":
        """Create a new empty encrypted vault; refuse to clobber an existing file."""
        if not passphrase:
            raise ValueError("vault passphrase must not be empty")
        p = Path(path)
        if p.exists():
            raise FileExistsError(f"vault already exists at {p}")
        p.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)  # ONE salt: stored in the envelope AND used to derive the key
        params = (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
        _write_vault(p, salt, _vault_key(passphrase, salt, *params), {}, params)
        return cls(p, passphrase)

    @classmethod
    def from_env(cls) -> "VaultBackend":
        path = os.environ.get("TOOLSTACK_VAULT_FILE") or _default_vault_file()
        return cls(path, _vault_passphrase())


@dataclass(frozen=True)
class InfisicalCredentials:
    client_id: str
    client_secret: str


def _load_infisical_credentials(path: Path) -> InfisicalCredentials:
    """Read a machine-identity credentials file (`KEY=value`, `#` comments)."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip().lower()] = value
    client_id = values.get("infisical_client_id") or values.get("client_id")
    client_secret = values.get("infisical_client_secret") or values.get("client_secret")
    if not client_id or not client_secret:
        raise ValueError(f"{path}: missing INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET")
    return InfisicalCredentials(client_id, client_secret)


class InfisicalBackend:
    """Resolve secrets from Infisical via its HTTP API (stdlib `urllib` only).

    Each tool authenticates with its own machine identity: a credentials file
    `<credentials_dir>/<item>.env` holding `INFISICAL_CLIENT_ID` /
    `INFISICAL_CLIENT_SECRET`. A `[[secrets]]` entry maps to an Infisical lookup of
    `vault` (project) / `item` (secret path) / `field` (secret key). `item` defaults
    to the tool id; `vault` falls back to `$TOOLSTACK_INFISICAL_VAULT`.
    """

    def __init__(
        self,
        *,
        host: str,
        credentials_dir: str | Path,
        environment: str = "prod",
        organization_slug: str | None = None,
        default_vault: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        if not host:
            raise ValueError("InfisicalBackend requires a host")
        self.host = host.rstrip("/")
        self.credentials_dir = Path(credentials_dir)
        self.environment = environment
        self.organization_slug = organization_slug
        self.default_vault = default_vault
        self.timeout = timeout
        self._tokens: dict[str, tuple[str, float]] = {}
        self._project_ids: dict[tuple[str, str], str] = {}

    @classmethod
    def from_env(cls) -> "InfisicalBackend":
        """Build from the `TOOLSTACK_INFISICAL_*` environment variables."""
        def env(name: str, default: str | None = None) -> str | None:
            return os.environ.get(f"TOOLSTACK_INFISICAL_{name}") or default

        host = env("HOST")
        if not host:
            raise ValueError("infisical backend needs TOOLSTACK_INFISICAL_HOST")
        creds_dir = env("CREDENTIALS_DIR") or str(
            Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
            / "toolstack" / "infisical"
        )
        return cls(
            host=host,
            credentials_dir=creds_dir,
            environment=env("ENVIRONMENT", "prod"),
            organization_slug=env("ORGANIZATION_SLUG"),
            default_vault=env("VAULT"),
        )

    def resolve(self, tool_def: ToolDef) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for spec in tool_def.secrets:
            vault = spec.vault or self.default_vault
            if not vault:
                raise ValueError(
                    f"{tool_def.id}.{spec.name}: no vault (set [[secrets]].vault "
                    "or $TOOLSTACK_INFISICAL_VAULT)"
                )
            item = spec.item or tool_def.id
            resolved[spec.name] = self._resolve_one(vault, item, spec.field)
        return resolved

    def update(self, tool_def: ToolDef, name: str, value: str) -> None:
        """Patch a writable field back to Infisical (message-contracts §4)."""
        spec = writable_spec(tool_def, name)
        vault = spec.vault or self.default_vault
        if not vault:
            raise ValueError(f"{tool_def.id}.{name}: no vault for write-back")
        item = spec.item or tool_def.id
        creds = self._credentials_for(item)
        project_id = self._project_id(creds, vault)
        path = "/" + item.strip("/") if item.strip("/") else "/"
        self._request(
            "PATCH",
            f"{self.host}/api/v4/secrets/{urllib.parse.quote(spec.field, safe='')}",
            self._auth(creds),
            {
                "projectId": project_id,
                "environment": self.environment,
                "secretValue": value,
                "secretPath": path,
                "type": "shared",
            },
        )

    # --- Infisical API ----------------------------------------------------------
    def _resolve_one(self, vault: str, item: str, field: str) -> str:
        creds = self._credentials_for(item)
        project_id = self._project_id(creds, vault)
        path = "/" + item.strip("/") if item.strip("/") else "/"
        params = {
            "projectId": project_id,
            "environment": self.environment,
            "secretPath": path,
            "viewSecretValue": "true",
            "expandSecretReferences": "true",
            "includeImports": "true",
        }
        payload = self._get("/api/v4/secrets", self._auth(creds), params)
        for secret in self._iter_secrets(payload):
            if secret.get("secretKey") == field:
                value = secret.get("secretValue")
                if not isinstance(value, str):
                    raise ValueError(f"Infisical {vault}{path}/{field} has no string value")
                return value
        raise KeyError(f"Infisical secret {vault}{path}/{field} not found")

    @staticmethod
    def _iter_secrets(payload: dict):
        if not isinstance(payload, dict):
            return
        for secret in payload.get("secrets") or []:
            if isinstance(secret, dict):
                yield secret
        for imported in payload.get("imports") or []:
            for secret in (imported.get("secrets") if isinstance(imported, dict) else None) or []:
                if isinstance(secret, dict):
                    yield secret

    def _credentials_for(self, item: str) -> InfisicalCredentials:
        stem = (item.strip("/") or "root").replace("/", "__")
        path = self.credentials_dir / f"{stem}.env"
        if not path.exists():
            raise FileNotFoundError(f"missing Infisical credentials for {item!r}: expected {path}")
        return _load_infisical_credentials(path)

    def _access_token(self, creds: InfisicalCredentials) -> str:
        now = time.time()
        cached = self._tokens.get(creds.client_id)
        if cached and now < cached[1] - 30:
            return cached[0]
        body = {"clientId": creds.client_id, "clientSecret": creds.client_secret}
        if self.organization_slug:
            body["organizationSlug"] = self.organization_slug
        payload = self._post("/api/v1/auth/universal-auth/login", {}, body)
        token = payload.get("accessToken")
        if not isinstance(token, str) or not token:
            raise ValueError("Infisical login response did not include accessToken")
        ttl = payload.get("expiresIn")
        ttl = float(ttl) if isinstance(ttl, (int, float)) else 600.0
        self._tokens[creds.client_id] = (token, now + ttl)
        return token

    def _auth(self, creds: InfisicalCredentials) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token(creds)}"}

    def _project_id(self, creds: InfisicalCredentials, vault: str) -> str:
        key = (creds.client_id, vault)
        if key in self._project_ids:
            return self._project_ids[key]
        payload = self._get("/api/v1/projects", self._auth(creds), {})
        for project in payload.get("projects") or []:
            if not isinstance(project, dict):
                continue
            ids = {project.get(k) for k in ("id", "_id", "name", "slug")}
            if vault in ids:
                pid = project.get("id") or project.get("_id")
                if not isinstance(pid, str) or not pid:
                    raise ValueError(f"Infisical project {vault!r} has no id")
                self._project_ids[key] = pid
                return pid
        raise KeyError(f"Infisical project {vault!r} not found")

    def _get(self, path: str, headers: dict[str, str], params: dict[str, str]) -> dict:
        url = f"{self.host}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._request("GET", url, headers, None)

    def _post(self, path: str, headers: dict[str, str], body: dict) -> dict:
        return self._request("POST", f"{self.host}{path}", headers, body)

    _RETRIES = 3  # total attempts for a transient (429 / 5xx / network) Infisical failure

    def _request(self, method: str, url: str, headers: dict[str, str], body: dict | None) -> dict:
        data = None
        headers = dict(headers)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        path = urllib.parse.urlparse(url).path
        transient: RuntimeError | None = None
        for attempt in range(self._RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:  # a subclass of URLError; catch it first
                code = exc.code
                exc.close()  # release the response; otherwise it leaks (ResourceWarning)
                if code in (401, 403):
                    raise RuntimeError(f"Infisical {method} {path}: HTTP {code}, auth failed "
                                       "(check the machine-identity credentials)") from exc
                if code != 429 and code < 500:
                    raise RuntimeError(f"Infisical {method} {path}: HTTP {code}") from exc
                transient = RuntimeError(f"Infisical {method} {path}: HTTP {code} (transient)")
            except urllib.error.URLError as exc:  # network/timeout, also transient
                transient = RuntimeError(f"Infisical {method} {path}: {exc.reason} (network)")
            if attempt < self._RETRIES - 1:
                time.sleep(0.25 * (2 ** attempt))  # 0.25s, 0.5s backoff before the retry
        raise transient  # exhausted retries on a transient error


def get_backend(name: str | None = None, *, secrets_file: str | Path | None = None):
    """Return a secret backend by name (default `$TOOLSTACK_SECRET_BACKEND` or `file`).

    `file` reads the dev TOML (`secrets_file` or `$TOOLSTACK_SECRETS_FILE`); `vault`
    opens the local encrypted vault (`$TOOLSTACK_VAULT_FILE` + passphrase from the env);
    `infisical` builds an `InfisicalBackend` from the environment.
    """
    name = name or os.environ.get("TOOLSTACK_SECRET_BACKEND", "file")
    if name == "file":
        path = secrets_file or os.environ.get("TOOLSTACK_SECRETS_FILE", "secrets.toml")
        return FileBackend(path)
    if name == "vault":
        return VaultBackend.from_env()
    if name == "infisical":
        return InfisicalBackend.from_env()
    raise ValueError(f"unknown secret backend: {name}")
