"""Hashicorp Vault KV-v2 plugin for SPS.

Stdlib HTTP only. Auth via `X-Vault-Token`. The mount is configurable
(default `secret`); path lookup is `/v1/<mount>/data/<item>`.

Writeback reads the complete item, preserves siblings and POSTs with the
observed KV-v2 version as compare-and-set. Conflicts fail without replay.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import quote, unquote

from ..config import VaultBlock, validate_provider_url
from .base import SPSSecretsPlugin
from .. import transport


class HashicorpVaultPlugin(SPSSecretsPlugin):
    def __init__(self, block: VaultBlock, *, timeout: float = 15.0) -> None:
        if not block.url or not block.token:
            raise ValueError("HashicorpVaultPlugin requires url/token")
        self.base = validate_provider_url(block.url)
        self.token = block.token
        self.mount = block.mount.strip("/")
        self.timeout = transport.valid_timeout(timeout)

    def connect(self):
        return self  # no pre-connect; X-Vault-Token rides every request

    def _headers(self) -> dict:
        return {"X-Vault-Token": self.token, "Accept": "application/json"}

    def _path(self, item: str) -> str:
        def encode(path):
            parts = path.split("/")
            if any(not p or unquote(p) in (".", "..") or
                   any(c in unquote(p) for c in "?#/\\") for p in parts):
                raise ValueError("unsafe Vault path")
            return "/".join(quote(p, safe="") for p in parts)
        return f"{self.base}/v1/{encode(self.mount)}/data/{encode(item)}"

    @transport.operation
    def get_secret(self, field: str, item: str) -> str:
        url = self._path(item)
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        with transport.urlopen(req, timeout=transport._active.get().idle()) as resp:
            body = json.loads(transport.read_response(resp).decode("utf-8"))
        data = (body.get("data") or {}).get("data") or {}
        if field not in data:
            raise KeyError(f"Vault {url} has no field {field!r}")
        return str(data[field])

    @transport.operation
    def write_secret(self, field: str, item: str, value: str) -> None:
        url = self._path(item)
        read = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with transport.urlopen(read, timeout=transport._active.get().idle()) as resp:
                current = json.loads(transport.read_response(resp).decode("utf-8"))["data"]
            data = dict(current["data"])
            version = current["metadata"]["version"]
            if type(version) is not int or version < 1:
                raise ValueError("invalid Vault version")
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code != 404:
                raise
            data, version = {}, 0
        data[field] = value
        payload = {"data": data, "options": {"cas": version}}
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={**self._headers(), "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with transport.urlopen(req, timeout=transport._active.get().idle()) as resp:
                transport.read_response(resp)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"Vault write {url}: HTTP {exc.code}") from exc
