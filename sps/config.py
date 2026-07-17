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
from dataclasses import dataclass
from pathlib import Path


class ConfigModeError(RuntimeError):
    """The sps.env file exists but is not mode 0600."""


@dataclass(frozen=True)
class InfisicalBlock:
    host: str
    vault: str
    environment: str = "prod"
    organization_slug: str | None = None
    client_id: str = ""
    client_secret: str = ""


@dataclass(frozen=True)
class VaultBlock:
    url: str
    token: str
    mount: str = "secret"


@dataclass(frozen=True)
class LocalFileBlock:
    vault_file: str


@dataclass(frozen=True)
class Config:
    sp_host: str
    sp_port: int
    sp_secret: str
    sp_tls_cert: str
    sp_tls_key: str
    sp_tls_ca: str
    sp_audit_log: str
    sp_plugin: str
    infisical: InfisicalBlock | None
    vault: VaultBlock | None
    localfile: LocalFileBlock | None


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
    )
