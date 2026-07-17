"""Hashicorp Vault KV-v2 plugin for SPS.

Stdlib HTTP only. Auth via `X-Vault-Token`. The mount is configurable
(default `secret`); path lookup is `/v1/<mount>/data/<item>`.

Writeback uses POST (KV-v2 accepts POST for create or patch with a full
data object).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..config import VaultBlock
from .base import SPSSecretsPlugin


class HashicorpVaultPlugin(SPSSecretsPlugin):
    def __init__(self, block: VaultBlock, *, timeout: float = 15.0) -> None:
        if not block.url or not block.token:
            raise ValueError("HashicorpVaultPlugin requires url/token")
        self.base = block.url.rstrip("/")
        self.token = block.token
        self.mount = block.mount.strip("/")
        self.timeout = timeout

    def connect(self):
        return self  # no pre-connect; X-Vault-Token rides every request

    def _headers(self) -> dict:
        return {"X-Vault-Token": self.token, "Accept": "application/json"}

    def _path(self, item: str) -> str:
        return f"{self.base}/v1/{self.mount}/data/{item.strip('/')}"

    def get_secret(self, field: str, item: str) -> str:
        url = self._path(item)
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        data = (body.get("data") or {}).get("data") or {}
        if field not in data:
            raise KeyError(f"Vault {url} has no field {field!r}")
        return str(data[field])

    def write_secret(self, field: str, item: str, value: str) -> None:
        url = self._path(item)
        payload = {"data": {field: value}}
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={**self._headers(), "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"Vault write {url}: HTTP {exc.code}") from exc
