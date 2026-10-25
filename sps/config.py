"""Parse /etc/toolstack/sps.env into typed config.

The file MUST be mode 0600 (the guidance is explicit: a misconfigured file
returns an error envelope to every register/unregister call regardless of
SP_SECRET contents). Plugin-specific config lives in [section] blocks; we
surface a small per-plugin dataclass only for the three shipped plugins.
"""
from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress


def strict_bool(value: bool | str) -> bool:
    """Shared TLS verification parser. Invalid values never disable verification."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    raise ValueError("expected a strict boolean")


def parse_bool(value: bool | str, *, name: str = "boolean") -> bool:
    try:
        return strict_bool(value)
    except ValueError as exc:
        raise ValueError(f"{name}: expected a strict boolean") from exc


def validate_provider_url(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname
    local = host == "localhost"
    try:
        local = local or ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        pass
    if (not host or parsed.username or parsed.password or parsed.query or
            parsed.fragment or parsed.scheme not in ("https", "http") or
            (parsed.scheme == "http" and not local)):
        raise ValueError("provider URL requires HTTPS (HTTP allowed only on loopback)")
    return value.rstrip("/")


class ConfigModeError(RuntimeError):
    """The sps.env file exists but is not mode 0600."""


@dataclass(frozen=True)
class InfisicalBlock:
    host: str
    vault: str
    environment: str = "prod"
    organization_slug: str | None = None
    client_id: str = ""
    client_secret: str = field(default="", repr=False)


@dataclass(frozen=True)
class VaultBlock:
    url: str
    token: str = field(repr=False)
    mount: str = "secret"


@dataclass(frozen=True)
class LocalFileBlock:
    vault_file: str


@dataclass(frozen=True)
class Config:
    sp_host: str
    sp_port: int
    sp_secret: str = field(repr=False)
    sp_tls_cert: str
    sp_tls_key: str
    sp_tls_ca: str
    sp_audit_log: str
    sp_plugin: str
    infisical: InfisicalBlock | None
    vault: VaultBlock | None
    localfile: LocalFileBlock | None
    grants: dict[str, tuple[str, ...]] = field(default_factory=dict)
    sp_max_value_bytes: int = 65536
    sp_allow_nonloopback: bool = False


def validate_listener(host: str, allow_nonloopback: bool = False) -> None:
    local = host == "localhost"
    try:
        local = local or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if not local and not allow_nonloopback:
        raise ValueError("non-loopback SP_HOST requires SP_ALLOW_NONLOOPBACK")


_ALLOWED_PLUGINS = ("infisical", "hashicorp_vault", "localfile")


def _check_mode(path: Path) -> None:
    """Reject anything that is not exactly mode 0600 (regular file, owner read/write only)."""
    st = os.stat(path)
    if stat.S_ISDIR(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ConfigModeError(f"{path}: not a regular file")
    if (st.st_mode & 0o777) != 0o600:
        raise ConfigModeError(
            f"{path}: must be mode 0600 (got {oct(st.st_mode & 0o777)}); refusing to load SP_SECRET"
        )


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    _check_mode(p)
    with open(p, "rb") as f:
        data = tomllib.load(f)

    def _need(key: str) -> str:
        v = data.get(key)
        if not isinstance(v, str) or not v:
            raise ValueError(f"{p}: missing required key {key!r}")
        return v

    sp_host = _need("SP_HOST")
    allow_nonloopback = strict_bool(data.get("SP_ALLOW_NONLOOPBACK", False))
    validate_listener(sp_host, allow_nonloopback)
    grants = data.get("grants", {})
    if not isinstance(grants, dict) or any(
        not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items)
        for items in grants.values()
    ):
        raise ValueError("grants must map tool ids to arrays of non-empty items")
    max_value = data.get("SP_MAX_VALUE_BYTES", 65536)
    if isinstance(max_value, bool) or not isinstance(max_value, int) or max_value < 1:
        raise ValueError("SP_MAX_VALUE_BYTES must be a positive integer")
    sp_port = int(_need("SP_PORT"))
    sp_secret = _need("SP_SECRET")
    sp_tls_cert = data.get("SP_TLS_CERT", "")
    sp_tls_key = data.get("SP_TLS_KEY", "")
    sp_tls_ca = data.get("SP_TLS_CA", "")
    sp_audit_log = data.get("SP_AUDIT_LOG", "")
    sp_plugin = data.get("SP_PLUGIN", "")
    if sp_plugin not in _ALLOWED_PLUGINS:
        raise ValueError(
            f"{p}: SP_PLUGIN must be one of {', '.join(_ALLOWED_PLUGINS)} "
            f"(got {sp_plugin!r})"
        )

    ifi_raw = data.get("infisical")
    infisical = (
        InfisicalBlock(
            host=ifi_raw["HOST"],
            vault=ifi_raw["VAULT"],
            environment=ifi_raw.get("ENVIRONMENT", "prod"),
            organization_slug=ifi_raw.get("ORGANIZATION_SLUG"),
            client_id=ifi_raw.get("CLIENT_ID", ""),
            client_secret=ifi_raw.get("CLIENT_SECRET", ""),
        )
        if isinstance(ifi_raw, dict)
        else None
    )

    vault_raw = data.get("hashicorp_vault")
    vault = (
        VaultBlock(
            url=vault_raw["URL"],
            token=vault_raw["TOKEN"],
            mount=vault_raw.get("MOUNT", "secret"),
        )
        if isinstance(vault_raw, dict)
        else None
    )

    lf_raw = data.get("localfile")
    localfile = (
        LocalFileBlock(vault_file=lf_raw["VAULT_FILE"])
        if isinstance(lf_raw, dict)
        else None
    )

    return Config(
        sp_host=sp_host,
        sp_port=sp_port,
        sp_secret=sp_secret,
        sp_tls_cert=sp_tls_cert,
        sp_tls_key=sp_tls_key,
        sp_tls_ca=sp_tls_ca,
        sp_audit_log=sp_audit_log,
        sp_plugin=sp_plugin,
        infisical=infisical,
        vault=vault,
        localfile=localfile,
        grants={tool: tuple(items) for tool, items in grants.items()},
        sp_max_value_bytes=max_value,
        sp_allow_nonloopback=allow_nonloopback,
    )
