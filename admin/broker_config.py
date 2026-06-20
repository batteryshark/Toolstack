"""The broker run-config the admin app owns and supervises the broker from.

This captures every environment variable the broker reads at startup (see
``broker/server.py``: ``TOOLSTACK_BROKER_PORT`` / ``_DB`` / ``_TOOLS_ROOT`` /
``_NOD_URL`` / ``_NOD_TOKEN`` / ``_NOD_CHANNEL`` / ``_APPROVAL_TTL`` /
``_RATE_LIMIT``). The admin app persists it to a TOML file, turns it into the
broker child's environment via :meth:`to_env`, and points its own ``Store`` at
the same ``db_path``, so there is one source of truth for where broker data lives.

The nod issuer token is a secret: it is written to the ``0600`` config file but
never rendered back to the browser (see :meth:`masked`).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from broker.store import default_db_path

from . import settings

log = logging.getLogger(__name__)


def validate_nod_url(url: str) -> None:
    """Guard the one config field that points the broker outward: ``nod_url`` is where the
    broker sends approval cards **carrying the nod issuer token**, so a hostile value is an
    SSRF + token-exfil primitive. Reject anything that isn't a plain routable http(s) target.
    Empty is allowed (it means "no approval surface"). Raises ``ValueError`` on a bad URL.

    Plain ``http`` is permitted only for loopback (local dev); everything else must be
    ``https``. Literal link-local / cloud-metadata (169.254.169.254, fe80::/10), multicast,
    reserved, and unspecified (0.0.0.0) addresses are refused outright."""
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("nod_url must be an http(s) URL")
    host = parsed.hostname
    if not host:
        raise ValueError("nod_url must include a host")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None  # a hostname, not a literal IP
    if ip is None:
        # Catch non-dotted IPv4 spellings (decimal / octal / hex) that ipaddress rejects but the
        # resolver accepts: e.g. http://2852039166/ resolves to 169.254.169.254 (cloud metadata).
        try:
            ip = ipaddress.ip_address(socket.inet_aton(host))
        except (OSError, ValueError):
            ip = None
    loopback = host == "localhost" or (ip is not None and ip.is_loopback)
    if parsed.scheme == "http" and not loopback:
        raise ValueError("nod_url must use https (plain http is allowed only for loopback)")
    if ip is not None and (ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        raise ValueError("nod_url host is not a routable address (link-local / metadata / reserved)")
    # NOTE: a *hostname* whose DNS points at metadata/internal space is not blocked here; the
    # broker (not the admin) is the eventual requester, and DNS can rebind after this check; the
    # https requirement is the backstop for hostname targets.


@dataclass
class BrokerRunConfig:
    port: int = 8765
    db_path: str = field(default_factory=default_db_path)
    tools_root: str = "tools"
    nod_url: str = ""
    nod_token: str = ""
    nod_channel: str = ""  # nod channel id; empty -> the broker's "default"
    approval_ttl: int = 3600
    rate_limit: int = 120
    tool_dirs: list[str] = field(default_factory=list)  # extra per-tool dirs (any path)

    def to_env(self) -> dict[str, str]:
        """The ``TOOLSTACK_*`` environment for spawning the broker. Empty optional
        values are omitted so the broker falls back to its own defaults (and so an
        empty nod config means 'no approval surface', exactly as today)."""
        env = {
            "TOOLSTACK_BROKER_PORT": str(self.port),
            "TOOLSTACK_BROKER_DB": self.db_path,
            "TOOLSTACK_TOOLS_ROOT": self.tools_root,
            "TOOLSTACK_APPROVAL_TTL": str(self.approval_ttl),
            "TOOLSTACK_RATE_LIMIT": str(self.rate_limit),
        }
        if self.nod_url:
            env["TOOLSTACK_NOD_URL"] = self.nod_url
        if self.nod_token:
            env["TOOLSTACK_NOD_TOKEN"] = self.nod_token
        if self.nod_channel:
            env["TOOLSTACK_NOD_CHANNEL"] = self.nod_channel
        if self.tool_dirs:
            env["TOOLSTACK_TOOLS_DIRS"] = os.pathsep.join(self.tool_dirs)
        return env

    def build_surface(self):
        """A `NodSurface` from this config, or None if nod isn't configured. The admin
        app revokes out of the broker process, so it builds its own surface client to
        withdraw cancelled approvals from nod."""
        if not (self.nod_url and self.nod_token):
            return None
        from broker.surface_nod import NodSurface
        return NodSurface(self.nod_url, self.nod_token, channel=self.nod_channel or "default")

    def masked(self) -> dict:
        """A dict safe to render in the browser: the nod token is never echoed,
        only its presence ('set' / 'not set')."""
        data = asdict(self)
        data["nod_token"] = "set" if self.nod_token else "not set"
        return data


def config_file() -> Path:
    return settings.config_dir() / "broker.toml"


def load() -> BrokerRunConfig:
    """Load the saved run-config, or the defaults if none has been saved yet.

    ``db_path`` is coerced to an absolute path: the admin and the broker start from
    possibly-different working directories, so a relative ``db_path`` would resolve to
    two different SQLite files (the admin's store and the broker's would silently
    diverge). Absolutising once here keeps the single-source-of-truth invariant."""
    path = config_file()
    if not path.exists():
        cfg = BrokerRunConfig()
    else:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        fields = BrokerRunConfig.__dataclass_fields__
        cfg = BrokerRunConfig(**{k: v for k, v in data.items() if k in fields})
    cfg.db_path = os.path.abspath(os.path.expanduser(cfg.db_path))
    _warn_if_suspect(cfg)
    return cfg


def _warn_if_suspect(cfg: BrokerRunConfig) -> None:
    """Log (don't raise) on a hand-edited broker.toml that bypassed the save-path validation;
    surfaces a misconfig without bricking load() (every code path calls it, incl. the page that
    would let the operator fix it)."""
    if not 1 <= cfg.port <= 65535:
        log.warning("broker config: port %r is out of range 1..65535", cfg.port)
    if cfg.approval_ttl < 1:
        log.warning("broker config: approval_ttl %r is < 1", cfg.approval_ttl)
    if cfg.rate_limit < 0:
        log.warning("broker config: rate_limit %r is < 0", cfg.rate_limit)
    try:
        validate_nod_url(cfg.nod_url)
    except ValueError as exc:
        log.warning("broker config: nod_url is invalid (%s)", exc)


def save(config: BrokerRunConfig) -> None:
    path = config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_to_toml(asdict(config)), encoding="utf-8")
    path.chmod(0o600)  # holds the nod token


def _toml_str(value) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _to_toml(data: dict) -> str:
    """Serialize a flat dict of str/int/bool/list-of-str values to TOML (stdlib has
    a reader but no writer; our config is flat, so this stays tiny)."""
    lines = []
    for key, value in data.items():
        if isinstance(value, bool):  # before int: bool is a subclass of int
            lines.append(f"{key} = {str(value).lower()}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        elif isinstance(value, list):
            lines.append(f"{key} = [{', '.join(_toml_str(v) for v in value)}]")
        else:
            lines.append(f"{key} = {_toml_str(value)}")
    return "\n".join(lines) + "\n"
