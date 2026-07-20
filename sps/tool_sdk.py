"""Tool-side SDK for talking to SPS over TLS/TCP.

Tools do this at boot:

    from sps.tool_sdk import SecretClient
    secrets = SecretClient.from_env("my_tool_id")
    api_key = secrets.get("api_key")

The `_cache` is the only thing the tool reads. To re-acquire (e.g., after a
writeback elsewhere, on operator demand, or on TTL), call `refresh(name)`
or `refresh_all()`. To update a backend value, call `writeback(name, value)`.

Read env vars at construction time (`TOOLSTACK_E_SECRET`, `TOOLSTACK_SPS_HOST`,
`TOOLSTACK_SPS_PORT`, `TOOLSTACK_SPS_CA`, `TOOLSTACK_SPS_VERIFY`). We don't
watch for env var changes after that.
"""
from __future__ import annotations

import os
from typing import Optional

from sps.client import SPSClient


_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8743


class SecretClient:
    def __init__(self, tool_id: str, *, host: str, port: int,
                 esecret: str, ca_file: str | None = None,
                 verify: bool = True) -> None:
        self._tool_id = tool_id
        self._esecret = esecret
        self._cli = SPSClient(host=host, port=port,
                             esecret=esecret, ca_file=ca_file,
                             verify=verify)
        body = self._cli.get_secrets(tool_id)
        # The wire response is {"status": "ok", "secrets": {...}}; other shapes
        # (an error envelope) raise inside the client.
        self._cache: dict[str, str] = dict(body.get("secrets", {}))

    @classmethod
    def from_env(cls, tool_id: str) -> "SecretClient":
        if os.environ.get("TOOLSTACK_SPS_FAKE") == "1":
            # Test fixture: skip the SPS roundtrip. Used by toolyard/tests so the
            # tool can boot without a real server. Production never sets this.
            obj = cls.__new__(cls)
            obj._tool_id = tool_id
            obj._esecret = "test-fixture-esecret"
            obj._cli = None  # type: ignore[assignment]
            obj._cache = {}
            return obj
        esecret = os.environ.get("TOOLSTACK_E_SECRET")
        if not esecret:
            raise RuntimeError(
                "TOOLSTACK_E_SECRET is not set; cannot reach SPS"
            )
        host = os.environ.get("TOOLSTACK_SPS_HOST", _DEFAULT_HOST)
        port = int(os.environ.get("TOOLSTACK_SPS_PORT", str(_DEFAULT_PORT)))
        ca_file = os.environ.get("TOOLSTACK_SPS_CA")
        verify = os.environ.get("TOOLSTACK_SPS_VERIFY", "1") == "1"
        return cls(tool_id, host=host, port=port, esecret=esecret,
                   ca_file=ca_file, verify=verify)

    def get(self, name: str) -> str:
        """Cached lookup. Raises `KeyError` if the name wasn't registered."""
        if name not in self._cache:
            raise KeyError(f"{self._tool_id}.{name} not registered with SPS")
        return self._cache[name]

    def cache_get(self, name: str) -> Optional[str]:
        """Read-only cache hit. Returns None if absent."""
        return self._cache.get(name)

    def refresh(self, name: str) -> str:
        """Force-refresh one secret from SPS and update the cache."""
        body = self._cli.get_secret(self._tool_id, name)
        value = body.get("secrets", {}).get(name, "")
        self._cache[name] = value
        return value

    def refresh_all(self) -> None:
        """Force-refresh the entire cache from SPS."""
        body = self._cli.get_secrets(self._tool_id)
        self._cache.clear()
        self._cache.update(body.get("secrets", {}))

    def writeback(self, name: str, value: str) -> None:
        """PATCH the secret in SPS, then update the cache on success."""
        self._cli.write_secret(self._tool_id, name, value)
        self._cache[name] = value

    def names(self) -> tuple[str, ...]:
        """Tuple of all secret names registered for this tool."""
        return tuple(self._cache.keys())
