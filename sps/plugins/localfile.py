"""Encrypted local file plugin for SPS.

The local-file production path: an AES-encrypted-at-rest vault on disk.
Phase 5: the encryption layer (scrypt + Fernet) was lifted wholesale from
`toolyard.secrets.VaultBackend` so the SPS plugin has no dependency on
the legacy toolyard secrets module. The envelope format, KDF parameters,
and operator UX (vault-init / vault-set) are unchanged.

`cryptography` is imported lazily so the SPS stays stdlib-only when the
localfile plugin isn't used.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from ..config import LocalFileBlock
from .base import SPSSecretsPlugin


# --- Encryption layer (lifted from toolyard/secrets.py:90-176) ----------------

_VAULT_VERSION = 1
_SCRYPT_N = 2 ** 14            # ~16 MB, tens of ms: interactive-grade stretching
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024  # headroom for the params above (else scrypt errors)


def _fernet():
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "the localfile SPS plugin needs the 'cryptography' package. "
            "Install the extra: pip install 'toolstack[vault]'"
        ) from exc
    return Fernet, InvalidToken


def _vault_key(passphrase: str, salt: bytes, n: int = _SCRYPT_N,
               r: int = _SCRYPT_R, p: int = _SCRYPT_P) -> bytes:
    try:
        dk = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=32, maxmem=_SCRYPT_MAXMEM)
    except (ValueError, OverflowError) as exc:
        raise RuntimeError(f"vault: unsupported KDF parameters (n={n}, r={r}, p={p})") from exc
    return base64.urlsafe_b64encode(dk)


def _vault_passphrase() -> str:
    """Read the passphrase from SP_VAULT_PASSPHRASE (or its _FILE variant)."""
    direct = os.environ.get("SP_VAULT_PASSPHRASE")
    if direct:
        return direct
    path = os.environ.get("SP_VAULT_PASSPHRASE_FILE")
    if path:
        value = Path(path).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(f"{path}: vault passphrase file is empty")
        return value
    raise ValueError(
        "localfile SPS plugin needs SP_VAULT_PASSPHRASE or SP_VAULT_PASSPHRASE_FILE"
    )


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
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class _Vault:
    """Encrypted-at-rest store: {tool_id: {field: value}}. JSON envelope
    (scrypt salt+params, Fernet ciphertext). Phase 5: the class formerly
    known as ``toolyard.secrets.VaultBackend``; same envelope, same KDF."""

    def __init__(self, path: str | Path, passphrase: str) -> None:
        self._path = Path(path)
        if not self._path.exists():
            raise FileNotFoundError(
                f"no vault at {self._path}: create one with `python3 -m sps.cli init`"
            )
        envelope = json.loads(self._path.read_text(encoding="utf-8"))
        if envelope.get("version") != _VAULT_VERSION:
            raise RuntimeError(
                f"vault {self._path}: unsupported version {envelope.get('version')!r} "
                f"(this build writes v{_VAULT_VERSION})"
            )
        self._salt = base64.urlsafe_b64decode(envelope["salt"])
        # Derive with the params the vault was WRITTEN with (read back from
        # the envelope), so changing the compiled-in defaults never bricks an
        # existing vault.
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

    def get(self, tool_id: str, field: str):
        return self._data.get(tool_id, {}).get(field)

    def has(self, tool_id: str, field: str) -> bool:
        return field in self._data.get(tool_id, {})

    def set(self, tool_id: str, field: str, value: str) -> None:
        self._data.setdefault(tool_id, {})[field] = value
        self._persist()

    def list_fields(self, tool_id: str) -> tuple[str, ...]:
        return tuple(self._data.get(tool_id, {}).keys())

    @classmethod
    def init(cls, path: str | Path, passphrase: str) -> "_Vault":
        if not passphrase:
            raise ValueError("vault passphrase must not be empty")
        p = Path(path)
        if p.exists():
            raise FileExistsError(f"vault already exists at {p}")
        p.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        params = (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
        _write_vault(p, salt, _vault_key(passphrase, salt, *params), {}, params)
        return cls(p, passphrase)


# --- SPS plugin -------------------------------------------------------------

class LocalFilePlugin(SPSSecretsPlugin):
    def __init__(self, block: LocalFileBlock, *, passphrase: str | None = None) -> None:
        self._vault_file = block.vault_file
        self._passphrase = passphrase

    def connect(self):
        passphrase = self._passphrase
        if not passphrase:
            passphrase = _vault_passphrase()
        self._backend = _Vault(self._vault_file, passphrase)
        return self

    def get_secret(self, field: str, item: str) -> str:
        # _Vault stores {tool_id: {field: value}}. CS_TUPLE's `item` IS the
        # tool id; `field` is the backend's key under that tool.
        value = self._backend.get(item, field)
        if value is None:
            raise KeyError(f"local vault: {item}.{field} not found")
        return str(value)

    def write_secret(self, field: str, item: str, value: str) -> None:
        # operator-only: no writable allowlist (that's a runtime concern for
        # the tool-side writeback path).
        self._backend.set(item, field, value)
