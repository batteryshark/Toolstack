"""Encrypted local file plugin for SPS.

Reuses toolyard/secrets.VaultBackend (scrypt + Fernet) so the local-file
production path keeps the same envelope it had before. The plugin is a thin
adapter: connect -> ensure vault loaded; get_secret/write_secret -> delegate.

Imports `toolyard.secrets.VaultBackend` lazily so the `cryptography` extra
isn't pulled into services that don't use the localfile plugin.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path

from ..config import LocalFileBlock
from .base import SPSSecretsPlugin


class LocalFilePlugin(SPSSecretsPlugin):
    def __init__(self, block: LocalFileBlock, *, passphrase: str | None = None) -> None:
        self._vault_file = block.vault_file
        self._passphrase = passphrase

    def connect(self):
        secrets_mod = importlib.import_module("toolyard.secrets")
        passphrase = self._passphrase
        if not passphrase:
            passphrase = os.environ.get("SP_VAULT_PASSPHRASE")
        if not passphrase:
            passphrase = secrets_mod._vault_passphrase()
        self._backend = secrets_mod.VaultBackend(self._vault_file, passphrase)
        return self

    def get_secret(self, field: str, item: str) -> str:
        # VaultBackend stores {tool_id: {field: value}}. We address by item (the
        # CS_TUPLE contract; tool's "path" in the backend), not by field.
        data = self._backend._data.get(item, {})  # type: ignore[attr-defined]
        if field not in data:
            raise KeyError(f"local vault: {item}.{field} not found")
        return str(data[field])

    def write_secret(self, field: str, item: str, value: str) -> None:
        # operator-only: no writable allowlist (that's a runtime concern for
        # the tool-side writeback path).
        self._backend.set_secret(item, field, value)  # type: ignore[attr-defined]  
